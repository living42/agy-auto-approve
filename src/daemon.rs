use crate::{
    audit, config,
    reviewer::{Assessment, ReviewerPool},
};
use anyhow::{Context, Result, bail};
use fs2::FileExt;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{Mutex, Notify},
};

const LIMIT: usize = 1024 * 1024;

/// Read a single newline-terminated JSON line from UnixStream.
async fn read_line(stream: &mut BufReader<UnixStream>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let chunk = stream.fill_buf().await?;
        if chunk.is_empty() {
            bail!("Connection closed before newline");
        }
        let end = chunk.iter().position(|b| *b == b'\n').map(|n| n + 1);
        let n = end.unwrap_or(chunk.len());
        if bytes.len() + n > LIMIT {
            bail!("IPC message exceeds 1 MiB");
        }
        bytes.extend_from_slice(&chunk[..n]);
        stream.consume(n);
        if end.is_some() {
            return Ok(bytes);
        }
    }
}

/// Send a request JSON message over Unix domain socket to the daemon and await response.
pub async fn request(path: &Path, req: &Value, seconds: u64) -> Result<Value> {
    tokio::time::timeout(Duration::from_secs(seconds), async {
        let mut stream = UnixStream::connect(path).await?;
        stream.write_all(format!("{req}\n").as_bytes()).await?;
        let bytes = read_line(&mut BufReader::new(stream)).await?;
        Ok(serde_json::from_slice(&bytes)?)
    })
    .await
    .context("Daemon request timed out")?
}

async fn running_status_or_default(path: &Path) -> Result<Value> {
    if let Ok(v) = request(path, &json!({"action": "status"}), 2).await
        && v["status"] == "running"
    {
        Ok(v)
    } else {
        Ok(json!({"status": "running"}))
    }
}

/// Start the background approver daemon if not already running.
pub async fn start() -> Result<Value> {
    let path = config::socket_path();
    if let Ok(v) = request(&path, &json!({"action": "ping"}), 1).await
        && v["status"] == "pong"
    {
        return running_status_or_default(&path).await;
    }
    let startup_log = config::log_dir().join("daemon-startup.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&startup_log)
        .ok();

    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["daemon", "run"])
        .stdin(Stdio::null())
        .stdout(if let Some(ref f) = log_file {
            f.try_clone()
                .map(Stdio::from)
                .unwrap_or_else(|_| Stdio::null())
        } else {
            Stdio::null()
        })
        .stderr(if let Some(f) = log_file {
            Stdio::from(f)
        } else {
            Stdio::null()
        });

    let mut child = command.spawn().context("Cannot spawn daemon")?;
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if let Ok(v) = request(&path, &json!({"action": "ping"}), 1).await
            && v["status"] == "pong"
        {
            return running_status_or_default(&path).await;
        }
        if let Ok(Some(_)) = child.try_wait() {
            // A competing or stopping daemon may temporarily hold the lock.
            // Wait briefly and retry spawning until the deadline.
            tokio::time::sleep(Duration::from_millis(50)).await;
            if Instant::now() < until
                && let Ok(new_child) = command.spawn()
            {
                child = new_child;
            }
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    bail!(
        "Failed to start daemon within timeout; check {}",
        startup_log.display()
    )
}

/// Send an evaluation request to the daemon.
pub async fn review(payload: &Value) -> Result<Assessment> {
    review_traced(payload, &audit::request_id()).await
}

/// Send an evaluation request to the daemon with correlated audit tracing.
pub async fn review_traced(payload: &Value, id: &str) -> Result<Assessment> {
    start().await?;
    let req = json!({
        "action": "evaluate",
        "request_id": id,
        "toolCall": payload["toolCall"],
        "workspacePaths": payload["workspacePaths"],
        "conversationId": payload.get("conversationId").or_else(|| payload.get("conversation_id")),
    });
    let timeout_secs = config::eval_timeout() + 10;
    let v = request(&config::socket_path(), &req, timeout_secs).await?;
    let a: Assessment =
        serde_json::from_value(v["assessment"].clone()).context("Invalid daemon assessment")?;
    if !matches!(a.outcome.as_str(), "allow" | "deny" | "ask" | "force_ask") {
        bail!("Invalid daemon decision");
    }
    Ok(a)
}

/// Internal shared state for the background daemon.
struct State {
    pool: Mutex<ReviewerPool>,
    stop: Notify,
    started: Instant,
    last_active: Mutex<Instant>,
    requests: AtomicU64,
    active: AtomicU64,
    idle_timeout: u64,
}

/// Handle a single incoming IPC client connection over Unix domain socket.
async fn handle(stream: UnixStream, state: Arc<State>) {
    let mut stream = BufReader::new(stream);
    let response: Result<Value> = async {
        let bytes = tokio::time::timeout(Duration::from_secs(5), read_line(&mut stream)).await??;
        let req: Value = serde_json::from_slice(&bytes)?;
        *state.last_active.lock().await = Instant::now();
        let action = req["action"].as_str().unwrap_or("");
        match action {
            "ping" => Ok(json!({"status": "pong"})),
            "status" => {
                let pool = state.pool.lock().await;
                let convs = pool.status_snapshot();
                Ok(json!({
                    "status": "running",
                    "pid": std::process::id(),
                    "socket": config::socket_path(),
                    "version": env!("CARGO_PKG_VERSION"),
                    "uptime_seconds": state.started.elapsed().as_secs(),
                    "idle_timeout_seconds": state.idle_timeout,
                    "evaluations": state.requests.load(Ordering::Relaxed),
                    "active_evaluations": state.active.load(Ordering::Relaxed),
                    "conversations": convs,
                }))
            }
            "flush" => {
                let mut pool = state.pool.lock().await;
                let flushed = pool.flush_all();
                Ok(json!({
                    "status": "ok",
                    "flushed_count": flushed,
                }))
            }
            "stop" => {
                let mut pool = state.pool.lock().await;
                pool.flush_all();
                Ok(json!({"status": "stopping"}))
            }
            "evaluate" => {
                state.requests.fetch_add(1, Ordering::Relaxed);
                state.active.fetch_add(1, Ordering::Relaxed);
                let id = req["request_id"].as_str().unwrap_or("unknown").to_string();

                let source_cid = req["conversationId"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .or(req["conversation_id"].as_str())
                    .filter(|s| !s.is_empty())
                    .unwrap_or("default");

                let prepared = {
                    let mut pool = state.pool.lock().await;
                    pool.prepare_turn(&req, &id).await
                };

                let evaluation = match prepared {
                    Ok((worker_arc, action_json, source_cid)) => {
                        let eval_timeout = Duration::from_secs(config::eval_timeout() + 5);
                        let eval_result = tokio::time::timeout(eval_timeout, async {
                            let mut worker = worker_arc.lock().await;
                            worker.evaluate_turn(&action_json, &id).await
                        })
                        .await;

                        match eval_result {
                            Ok(Ok(assessment)) => assessment,
                            Ok(Err(e)) => {
                                audit::record(
                                    &id,
                                    "reviewer_turn_error",
                                    json!({
                                        "source_cid": source_cid,
                                        "error": e.to_string(),
                                    }),
                                );
                                {
                                    let mut pool = state.pool.lock().await;
                                    pool.remove_worker(&source_cid);
                                }
                                Assessment::deny(format!("Reviewer evaluation failed: {e:#}"))
                            }
                            Err(_) => {
                                {
                                    let mut pool = state.pool.lock().await;
                                    pool.remove_worker(&source_cid);
                                }
                                Assessment::deny("Review deadline exceeded")
                            }
                        }
                    }
                    Err(e) => {
                        audit::record(
                            &id,
                            "reviewer_spawn_error",
                            json!({
                                "source_cid": source_cid,
                                "error": e.to_string(),
                            }),
                        );
                        Assessment::deny(format!("Failed to start reviewer process: {e:#}"))
                    }
                };

                audit::record(&id, "daemon_result", json!({"assessment": evaluation}));
                state.active.fetch_sub(1, Ordering::Relaxed);
                *state.last_active.lock().await = Instant::now();
                Ok(json!({"status": "ok", "assessment": evaluation}))
            }
            _ => Ok(json!({"status": "error", "message": "Unknown action"})),
        }
    }
    .await;

    let v = response.unwrap_or_else(|e| {
        json!({
            "status": "error",
            "assessment": Assessment::deny(format!("Daemon internal error: {e}")),
        })
    });

    let _ = stream
        .get_mut()
        .write_all(format!("{v}\n").as_bytes())
        .await;
    let _ = stream.get_mut().shutdown().await;
    if v["status"] == "stopping" {
        state.stop.notify_one();
    }
}

/// RAII helper to clean up socket file upon daemon shutdown.
struct SocketCleanup(std::path::PathBuf);
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Run the background approver daemon event loop.
pub async fn run(idle_timeout: u64) -> Result<()> {
    let path = config::socket_path();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)?;

    // Lifetime lock prevents concurrent starts from replacing a live socket.
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path.with_extension("sock.lock"))?;
    lock.try_lock_exclusive()
        .context("Another daemon owns this socket")?;

    if let Ok(meta) = fs::symlink_metadata(&path) {
        if !meta.file_type().is_socket() {
            bail!("Refusing to replace non-socket path {}", path.display());
        }
        if UnixStream::connect(&path).await.is_ok() {
            bail!("A daemon already listens on {}", path.display());
        }
        fs::remove_file(&path)?;
    }

    let listener = UnixListener::bind(&path)?;
    let _cleanup = SocketCleanup(path.clone());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

    let state = Arc::new(State {
        pool: Mutex::new(ReviewerPool::default()),
        stop: Notify::new(),
        started: Instant::now(),
        last_active: Mutex::new(Instant::now()),
        requests: AtomicU64::new(0),
        active: AtomicU64::new(0),
        idle_timeout,
    });

    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    // Check for idle reviewer workers and daemon idle timeout every second.
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut clients = tokio::task::JoinSet::new();

    eprintln!("Approver daemon listening on {}", path.display());
    loop {
        tokio::select! {
            conn = listener.accept() => {
                let (stream, _) = conn?;
                clients.spawn(handle(stream, state.clone()));
            }
            _ = state.stop.notified() => break,
            _ = term.recv() => break,
            _ = tokio::signal::ctrl_c() => break,
            _ = clients.join_next(), if !clients.is_empty() => {},
            _ = tick.tick() => {
                // Reclaim reviewer processes inactive for 10 minutes (600 seconds).
                state.pool.lock().await.reclaim_idle(Duration::from_secs(600));

                if idle_timeout > 0
                    && state.active.load(Ordering::Relaxed) == 0
                    && state.last_active.lock().await.elapsed().as_secs() >= idle_timeout
                {
                    break;
                }
            }
        }
    }

    // Flush and clean up all child workers on shutdown.
    state.pool.lock().await.flush_all();
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    Ok(())
}
