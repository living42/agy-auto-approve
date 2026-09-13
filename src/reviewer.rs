use crate::{audit, config, parser, pipeline::ConversationState};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    process::Stdio,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines},
    process::{Child, ChildStdin, ChildStdout, Command},
};

/// Security evaluation assessment returned by the LLM evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assessment {
    pub outcome: String,
    pub risk_level: String,
    pub user_authorization: String,
    pub rationale: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_stage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewer_cid: Option<String>,
}

impl Assessment {
    /// Construct a fail-closed deny assessment with an explanation.
    pub fn deny(reason: impl std::fmt::Display) -> Self {
        Self {
            outcome: "deny".into(),
            risk_level: "high".into(),
            user_authorization: "unknown".into(),
            rationale: format!("Fail-closed: {reason}"),
            error_stage: Some("reviewer".into()),
            reviewer_cid: None,
        }
    }
}

/// JSON Schema passed to the `agy` CLI to enforce structured output.
pub const GUARDIAN_OUTPUT_SCHEMA: &str = r#"{"type":"object","properties":{"risk_level":{"type":"string","enum":["low","medium","high","critical"]},"user_authorization":{"type":"string","enum":["unknown","low","medium","high"]},"outcome":{"type":"string","enum":["allow","deny"]},"rationale":{"type":"string"}},"required":["risk_level","user_authorization","outcome","rationale"]}"#;

/// Parse raw text or JSON into an Assessment struct.
/// Extracts JSON objects from markdown fences or text substrings if needed.
pub fn parse(raw: &str) -> Assessment {
    if raw.trim().is_empty() {
        return Assessment::deny("LLM review completed without an assessment payload");
    }
    let mut data = serde_json::from_str::<Value>(raw.trim()).ok();
    if data.is_none() {
        let fence = regex::Regex::new(r"(?s)```(?:json)?\s*(.*?)\s*```").unwrap();
        if let Some(c) = fence.captures(raw) {
            data = serde_json::from_str(c[1].trim()).ok();
        }
    }
    if data.is_none()
        && let (Some(a), Some(b)) = (raw.find('{'), raw.rfind('}'))
        && a < b
    {
        data = serde_json::from_str(&raw[a..=b]).ok();
    }
    let Some(v) = data.filter(Value::is_object) else {
        return Assessment::deny("Assessment payload was not valid JSON");
    };

    let outcome_value = v
        .get("outcome")
        .filter(|value| match value {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) => n.as_f64() != Some(0.0),
            Value::String(s) => !s.is_empty(),
            Value::Array(a) => !a.is_empty(),
            Value::Object(o) => !o.is_empty(),
        })
        .or_else(|| v.get("decision"));
    let outcome = outcome_value
        .and_then(Value::as_str)
        .unwrap_or("deny")
        .trim()
        .to_lowercase();
    let outcome = if matches!(outcome.as_str(), "allow" | "deny" | "ask" | "force_ask") {
        outcome
    } else {
        "deny".into()
    };
    let allow = outcome == "allow";
    Assessment {
        error_stage: None,
        reviewer_cid: None,
        outcome,
        risk_level: v["risk_level"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(if allow { "low" } else { "high" })
            .trim()
            .into(),
        user_authorization: v["user_authorization"]
            .as_str()
            .filter(|s| !s.is_empty())
            .unwrap_or("unknown")
            .trim()
            .into(),
        rationale: v["rationale"]
            .as_str()
            .filter(|s| !s.trim().is_empty())
            .or(v["reason"].as_str())
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(if allow {
                "Auto-review returned a low-risk allow decision."
            } else {
                "Auto-review returned a deny decision without a rationale."
            })
            .trim()
            .into(),
    }
}

/// Extract content of scripts invoked in a command line for deeper analysis.
pub fn script_content(cmd: &str, workspaces: &[Value]) -> String {
    for command in parser::commands(cmd) {
        for token in command.split_whitespace() {
            if ![
                ".sh", ".py", ".js", ".ts", ".bash", ".zsh", ".rb", ".mjs", ".cjs",
            ]
            .iter()
            .any(|ext| token.ends_with(ext))
            {
                continue;
            }
            let candidate = token.trim_matches(['\'', '"']);
            for ws in workspaces.iter().filter_map(Value::as_str) {
                if let Ok(bytes) = std::fs::read(PathBuf::from(ws).join(candidate)) {
                    let content: String =
                        String::from_utf8_lossy(&bytes).chars().take(4000).collect();
                    return format!(
                        "\n[Extracted Content of Script '{candidate}']:\n```\n{content}\n```\n"
                    );
                }
            }
        }
    }
    String::new()
}

/// Status of a tracked conversation for status reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConversationStatus {
    pub source_cid: String,
    pub reviewer_cid: Option<String>,
    pub project: String,
    pub process_state: String,
    pub pid: Option<u32>,
    pub idle_seconds: Option<u64>,
}

/// A background `agy` CLI process dedicated to reviewing a specific source conversation.
/// Runs in `~/.gemini/agy-auto-approve/state` with tool calls forbidden.
pub struct ReviewerWorker {
    pub source_cid: String,
    pub reviewer_cid: String,
    pub project: String,
    child: Child,
    stdin: ChildStdin,
    stdout: Lines<BufReader<ChildStdout>>,
    pub last_active: Instant,
    pub pid: u32,
}

impl ReviewerWorker {
    /// Spawn a new `agy` child process in stream-json mode.
    /// Resumes an existing conversation if `cached_reviewer_cid` is provided.
    pub async fn spawn(
        source_cid: &str,
        cached_reviewer_cid: Option<&str>,
        project: &str,
        id: &str,
    ) -> Result<Self> {
        let (model, effort) = config::model_and_effort();
        let bin = config::agy_bin();
        let state_dir = config::state_dir();
        fs::create_dir_all(&state_dir)?;

        let mut cmd = Command::new(&bin);
        cmd.current_dir(&state_dir)
            .arg("--input-format")
            .arg("stream-json")
            .arg("--output-format")
            .arg("stream-json")
            .arg("--disable-slash-commands")
            .arg("--sandbox")
            .arg("--model")
            .arg(&model)
            .arg("--effort")
            .arg(&effort)
            .arg("--json-schema")
            .arg(GUARDIAN_OUTPUT_SCHEMA);

        if let Some(rcid) = cached_reviewer_cid
            && !rcid.is_empty()
        {
            cmd.arg("--conversation").arg(rcid);
        }

        cmd.env("AGY_AUTO_APPROVE_INTERNAL", "1");

        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        audit::record(
            id,
            "reviewer_worker_spawn",
            json!({
                "source_cid": source_cid,
                "cached_reviewer_cid": cached_reviewer_cid,
                "project": project,
                "command": bin.display().to_string(),
                "cwd": state_dir.display().to_string(),
                "model": model,
                "effort": effort,
            }),
        );

        let mut child = cmd
            .spawn()
            .with_context(|| format!("Cannot spawn reviewer process using {}", bin.display()))?;

        let pid = child.id().unwrap_or(0);
        let stdin = child
            .stdin
            .take()
            .context("Cannot open child stdin for reviewer")?;
        let stdout_raw = child
            .stdout
            .take()
            .context("Cannot open child stdout for reviewer")?;
        let mut stdout = BufReader::new(stdout_raw).lines();

        // Read the initial "init" event from agy to capture the reviewer conversation ID.
        let reviewer_cid = tokio::time::timeout(Duration::from_secs(30), async {
            while let Some(line) = stdout.next_line().await? {
                if let Ok(data) = serde_json::from_str::<Value>(&line) {
                    if data["event"] == "init"
                        && let Some(cid) =
                            data["conversation_id"].as_str().filter(|s| !s.is_empty())
                    {
                        return Ok(cid.to_string());
                    }
                    if data["event"] == "result" && data["result"]["status"] == "ERROR" {
                        let err = data["result"]["error"].as_str().unwrap_or("Init failed");
                        bail!("agy CLI error during initialization: {err}");
                    }
                }
            }
            bail!("Reviewer stdout closed before init event received");
        })
        .await
        .context("Timeout waiting for reviewer init event")??;

        audit::record(
            id,
            "reviewer_worker_ready",
            json!({
                "source_cid": source_cid,
                "reviewer_cid": reviewer_cid,
                "pid": pid,
            }),
        );

        Ok(Self {
            source_cid: source_cid.to_string(),
            reviewer_cid,
            project: project.to_string(),
            child,
            stdin,
            stdout,
            last_active: Instant::now(),
            pid,
        })
    }

    /// Execute one evaluation turn over stream-json stdin and stdout.
    pub async fn evaluate_turn(&mut self, action_json: &str, id: &str) -> Result<Assessment> {
        let system_prompt = config::prompt();
        let prompt_text = format!(
            "{system_prompt}\n\n=== PROPOSED ACTION FOR REVIEW ===\n{action_json}\n\nREMINDER: You are a pure evaluator. You must NOT execute any tools. Return ONLY valid JSON matching the schema."
        );

        let msg = json!({
            "event": "user",
            "message": {
                "content": prompt_text,
            }
        });

        let mut line_to_send = serde_json::to_string(&msg)?;
        line_to_send.push('\n');

        self.stdin
            .write_all(line_to_send.as_bytes())
            .await
            .context("Cannot write to reviewer stdin")?;
        self.stdin
            .flush()
            .await
            .context("Cannot flush reviewer stdin")?;

        let started = Instant::now();
        let deadline = Duration::from_secs(config::eval_timeout());

        let assessment = tokio::time::timeout(deadline, async {
            let mut accumulated_response = String::new();

            while let Some(line) = self.stdout.next_line().await? {
                let Ok(data) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                let event = data["event"].as_str().unwrap_or("");

                if event == "step_update" {
                    let su = &data["step_update"];
                    let step_type = su["step_type"].as_str().unwrap_or("");

                    // Deny all tool calls except the built-in finish pseudo-tool.
                    if step_type == "tool" {
                        let tool_name = su["tool_name"].as_str().unwrap_or("");
                        if tool_name != "finish" {
                            audit::record(
                                id,
                                "reviewer_tool_call_violation",
                                json!({
                                    "tool_name": tool_name,
                                    "tool_info": su.get("tool_info"),
                                    "source_cid": self.source_cid,
                                }),
                            );
                            bail!("Reviewer attempted forbidden tool execution: {tool_name}");
                        }
                    }

                    if step_type == "agent_response"
                        && let Some(delta) = su["text_delta"].as_str()
                    {
                        accumulated_response.push_str(delta);
                    }
                } else if event == "result" {
                    let result_obj = &data["result"];
                    let status = result_obj["status"].as_str().unwrap_or("");

                    if status == "SUCCESS" {
                        let mut eval = if let Some(so) = result_obj.get("structured_output")
                            && so.is_object()
                        {
                            serde_json::from_value::<Assessment>(so.clone())
                                .unwrap_or_else(|_| parse(&accumulated_response))
                        } else if let Some(resp_str) = result_obj["response"].as_str() {
                            parse(resp_str)
                        } else {
                            parse(&accumulated_response)
                        };
                        eval.reviewer_cid = Some(self.reviewer_cid.clone());
                        return Ok(eval);
                    } else {
                        let err_msg = result_obj["error"]
                            .as_str()
                            .unwrap_or("Evaluation failed with error status");
                        bail!("Reviewer result returned error: {err_msg}");
                    }
                }
            }
            bail!("Reviewer stdout closed unexpectedly before result");
        })
        .await
        .context("Timeout waiting for reviewer evaluation result")??;

        self.last_active = Instant::now();
        audit::record(
            id,
            "reviewer_turn_finished",
            json!({
                "source_cid": self.source_cid,
                "reviewer_cid": self.reviewer_cid,
                "duration_ms": started.elapsed().as_millis(),
                "assessment": assessment,
            }),
        );
        Ok(assessment)
    }

    /// Kill and reap the child process.
    pub fn kill(&mut self) {
        let _ = self.child.start_kill();
        let _ = self.child.try_wait();
    }
}

/// Pool managing active reviewer processes indexed by source conversation ID.
#[derive(Default)]
pub struct ReviewerPool {
    workers: HashMap<String, std::sync::Arc<tokio::sync::Mutex<ReviewerWorker>>>,
}

impl ReviewerPool {
    /// Perform an evaluation for a request payload.
    /// Prepare request metadata, look up or spawn a worker process,
    /// and return the worker handle, serialized action JSON, and source CID.
    /// This method only holds the pool lock briefly during lookup/spawn.
    pub async fn prepare_turn(
        &mut self,
        req: &Value,
        id: &str,
    ) -> Result<(
        std::sync::Arc<tokio::sync::Mutex<ReviewerWorker>>,
        String,
        String,
    )> {
        let source_cid = req["conversationId"]
            .as_str()
            .filter(|s| !s.is_empty())
            .or(req["conversation_id"].as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("default")
            .to_string();

        let ws = req["workspacePaths"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        let paths = ws
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join(", ");

        let project = if !paths.is_empty() {
            paths.clone()
        } else if let Some(cwd) = req["toolCall"]["args"]["Cwd"].as_str() {
            cwd.to_string()
        } else {
            "Current Workspace".to_string()
        };

        let mut action = json!({
            "environment": {
                "workspace_paths": if paths.is_empty() { "Current Workspace" } else { &paths },
                "target_project": project,
            },
            "tool": req["toolCall"]["name"],
            "args": req["toolCall"]["args"],
        });

        if req["toolCall"]["name"] == "run_command" {
            let script = script_content(
                req["toolCall"]["args"]["CommandLine"]
                    .as_str()
                    .unwrap_or(""),
                &ws,
            );
            if !script.is_empty() {
                action["inspected_script"] = script.into();
            }
        }

        let action_json = action.to_string();

        // Check if existing worker is still alive.
        if let Some(worker_ref) = self.workers.get(&source_cid) {
            let is_alive = if let Ok(mut worker) = worker_ref.try_lock() {
                matches!(worker.child.try_wait(), Ok(None))
            } else {
                true
            };
            if !is_alive {
                self.workers.remove(&source_cid);
            }
        }

        // Spawn or resume worker if not present.
        let worker_arc = if !self.workers.contains_key(&source_cid) {
            let state = ConversationState::open(&config::state_dir(), &source_cid).ok();
            let cached_reviewer_cid = state.as_ref().and_then(|s| s.reviewer_cid());
            let current_project = state
                .as_ref()
                .map(|s| s.project())
                .filter(|p| !p.is_empty())
                .unwrap_or_else(|| project.clone());

            let worker = ReviewerWorker::spawn(
                &source_cid,
                cached_reviewer_cid.as_deref(),
                &current_project,
                id,
            )
            .await?;

            if let Ok(mut state) = ConversationState::open(&config::state_dir(), &source_cid) {
                let _ = state.set_reviewer_cid(&worker.reviewer_cid);
                if state.project().is_empty() {
                    let _ = state.set_project(&current_project);
                }
            }
            let arc = std::sync::Arc::new(tokio::sync::Mutex::new(worker));
            self.workers.insert(source_cid.clone(), arc.clone());
            arc
        } else {
            self.workers.get(&source_cid).unwrap().clone()
        };

        Ok((worker_arc, action_json, source_cid))
    }

    /// Remove a worker process from the active pool (e.g. after failure or termination).
    pub fn remove_worker(&mut self, source_cid: &str) {
        if let Some(worker_ref) = self.workers.remove(source_cid)
            && let Ok(mut worker) = worker_ref.try_lock()
        {
            worker.kill();
        }
    }

    /// Resumes or spawns an `agy` reviewer process for the source conversation.
    pub async fn evaluate(&mut self, req: &Value, id: &str) -> Assessment {
        let (worker_arc, action_json, source_cid) = match self.prepare_turn(req, id).await {
            Ok(tuple) => tuple,
            Err(e) => {
                audit::record(
                    id,
                    "reviewer_spawn_error",
                    json!({
                        "error": e.to_string(),
                    }),
                );
                return Assessment::deny(format!("Failed to start reviewer process: {e:#}"));
            }
        };

        // Execute evaluation turn with the active worker.
        let mut worker = worker_arc.lock().await;
        match worker.evaluate_turn(&action_json, id).await {
            Ok(assessment) => assessment,
            Err(e) => {
                audit::record(
                    id,
                    "reviewer_turn_error",
                    json!({
                        "source_cid": source_cid,
                        "error": e.to_string(),
                    }),
                );
                // Kill failed worker so next turn gets a clean restart.
                worker.kill();
                drop(worker);
                self.workers.remove(&source_cid);
                Assessment::deny(format!("Reviewer evaluation failed: {e:#}"))
            }
        }
    }

    /// Reclaim worker processes that have been idle for longer than `idle_limit`.
    /// Terminates the process to free memory while keeping conversation state on disk.
    pub fn reclaim_idle(&mut self, idle_limit: Duration) -> usize {
        let mut to_remove = Vec::new();
        for (cid, worker_ref) in self.workers.iter() {
            if let Ok(worker) = worker_ref.try_lock()
                && worker.last_active.elapsed() >= idle_limit
            {
                to_remove.push((
                    cid.clone(),
                    worker.pid,
                    worker.last_active.elapsed().as_secs(),
                ));
            }
        }

        let count = to_remove.len();
        for (cid, pid, idle_secs) in to_remove {
            if let Some(worker_ref) = self.workers.remove(&cid) {
                if let Ok(mut worker) = worker_ref.try_lock() {
                    worker.kill();
                }
                let dir = config::log_dir();
                if fs::create_dir_all(&dir).is_ok()
                    && let Ok(mut f) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(dir.join("auto-approve.log"))
                {
                    let _ = writeln!(
                        f,
                        "[{}] [RECLAIM] cid={} pid={} idle={}s | Terminated idle reviewer process",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        cid,
                        pid,
                        idle_secs,
                    );
                }
            }
        }
        count
    }

    /// Forcefully terminate all running reviewer processes.
    pub fn flush_all(&mut self) -> usize {
        let count = self.workers.len();
        for (cid, worker_ref) in self.workers.drain() {
            if let Ok(mut worker) = worker_ref.try_lock() {
                worker.kill();
                let dir = config::log_dir();
                if fs::create_dir_all(&dir).is_ok()
                    && let Ok(mut f) = OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(dir.join("auto-approve.log"))
                {
                    let _ = writeln!(
                        f,
                        "[{}] [FLUSH] cid={} pid={} | Flushed reviewer process",
                        chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                        cid,
                        worker.pid,
                    );
                }
            }
        }
        count
    }

    /// Return a status snapshot of all known conversations (both running and reclaimed).
    pub fn status_snapshot(&self) -> Vec<ConversationStatus> {
        let mut results = Vec::new();
        let state_dir = config::state_dir();

        if let Ok(entries) = fs::read_dir(&state_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                let Ok(data) = fs::read(&path) else {
                    continue;
                };
                let Ok(v) = serde_json::from_slice::<Value>(&data) else {
                    continue;
                };
                let source_cid = v["source_cid"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .or_else(|| {
                        path.file_stem()
                            .and_then(|s| s.to_str())
                            .filter(|s| !s.starts_with("cb_") && *s != "reviewer_session")
                    })
                    .unwrap_or("default")
                    .to_string();

                let reviewer_cid = v["reviewer_conversation_id"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned);

                let project = v["project"].as_str().unwrap_or("").to_string();

                if let Some(worker_ref) = self.workers.get(&source_cid) {
                    if let Ok(worker) = worker_ref.try_lock() {
                        let idle = worker.last_active.elapsed().as_secs();
                        results.push(ConversationStatus {
                            source_cid,
                            reviewer_cid: Some(worker.reviewer_cid.clone()),
                            project: if project.is_empty() {
                                worker.project.clone()
                            } else {
                                project
                            },
                            process_state: format!("Running (PID {}, idle {}s)", worker.pid, idle),
                            pid: Some(worker.pid),
                            idle_seconds: Some(idle),
                        });
                    } else {
                        results.push(ConversationStatus {
                            source_cid,
                            reviewer_cid,
                            project,
                            process_state: "Evaluating (Active)".into(),
                            pid: None,
                            idle_seconds: Some(0),
                        });
                    }
                } else {
                    results.push(ConversationStatus {
                        source_cid,
                        reviewer_cid,
                        project,
                        process_state: "Reclaimed (idle > 10m, will resume on demand)".into(),
                        pid: None,
                        idle_seconds: None,
                    });
                }
            }
        }

        // Sort by source_cid for consistent output.
        results.sort_by(|a, b| a.source_cid.cmp(&b.source_cid));
        results
    }
}
