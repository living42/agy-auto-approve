use agy_auto_approve::{audit, config, daemon, pipeline, register, upgrade};
use anyhow::{Result, bail};
use clap::{Parser, Subcommand};
use serde_json::{Value, json};
use std::io::Read;

#[derive(Parser)]
#[command(version, about = "Antigravity approval hook and daemon management")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Read a PreToolUse JSON payload on stdin; emit exactly one result on stdout.
    Hook,
    /// Read a PostToolUse JSON payload on stdin; emit `{}` on stdout.
    PostHook,
    /// List approval logs, or inspect the full input/output trace of one approval.
    #[command(args_conflicts_with_subcommands = true)]
    Logs {
        #[command(subcommand)]
        command: Option<LogsCommand>,
        #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(1..))]
        limit: u32,
        #[arg(long, value_parser = ["allow", "deny", "ask", "force_ask"])]
        decision: Option<String>,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        conversation: Option<String>,
        /// Print JSON summaries (an array normally, JSON Lines with --follow).
        #[arg(long)]
        json: bool,
        /// Print recent approvals, then follow newly completed approvals until Ctrl-C.
        #[arg(short, long)]
        follow: bool,
    },
    /// Start, inspect, stop, or run the approval daemon.
    Daemon {
        #[command(subcommand)]
        command: DaemonCommand,
    },
    /// Upgrade the executable and refresh installed plugin configuration.
    Update {
        #[arg(long)]
        version: Option<String>,
    },
    /// Register this executable for CLI and Desktop lifecycle hooks.
    Install {
        #[arg(long, conflicts_with = "desktop_only")]
        cli_only: bool,
        #[arg(long)]
        desktop_only: bool,
    },
}

#[derive(Subcommand)]
enum DaemonCommand {
    /// Start the background approver daemon if not running.
    Start,
    /// Inspect daemon status and list all tracked conversations.
    Status {
        /// Print status as raw JSON.
        #[arg(long)]
        json: bool,
    },
    /// Forcefully terminate all running background reviewer processes.
    Flush,
    /// Stop the background approver daemon.
    Stop,
    /// Run the daemon in foreground.
    Run {
        #[arg(long, default_value_t = 1800)]
        idle_timeout: u64,
    },
}

#[derive(Subcommand)]
enum LogsCommand {
    /// Show all recorded events for an exact approval ID, including reviewer input/output.
    Show { id: String },
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Hook => {
            let mut bytes = Vec::new();
            let parsed = std::io::stdin()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .ok()
                .filter(|_| bytes.len() <= 1024 * 1024)
                .and_then(|_| serde_json::from_slice::<Value>(&bytes).ok())
                .filter(Value::is_object);
            let result = match parsed {
                Some(payload)
                    if payload["toolCall"].is_object()
                        && payload["toolCall"]["name"].is_string()
                        && payload["toolCall"]["args"].is_object() =>
                {
                    pipeline::evaluate(&payload).await
                }
                Some(payload)
                    if payload.get("toolCall").is_none() || payload["toolCall"].is_null() =>
                {
                    pipeline::post_evaluate(&payload).await
                }
                Some(payload) => {
                    let id = audit::request_id();
                    audit::record(&id, "hook_input", json!({"invalid_payload": payload}));
                    let output = pipeline::result("ask", "Failed to parse hook stdin payload.", "");
                    audit::record(
                        &id,
                        "hook_result",
                        json!({
                            "tool": "",
                            "conversation_id": "default",
                            "stage": "invalid_input",
                            "output": output,
                            "duration_ms": 0,
                        }),
                    );
                    output
                }
                None => {
                    let id = audit::request_id();
                    audit::record(
                        &id,
                        "hook_input",
                        json!({
                            "raw_input": String::from_utf8_lossy(&bytes),
                            "truncated": bytes.len() > 1024 * 1024,
                        }),
                    );
                    let output = pipeline::result("ask", "Failed to parse hook stdin payload.", "");
                    audit::record(
                        &id,
                        "hook_result",
                        json!({
                            "tool": "",
                            "conversation_id": "default",
                            "stage": "invalid_input",
                            "output": output,
                            "duration_ms": 0,
                        }),
                    );
                    output
                }
            };
            println!("{result}");
        }
        Commands::PostHook => {
            let mut bytes = Vec::new();
            let parsed = std::io::stdin()
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .ok()
                .filter(|_| bytes.len() <= 1024 * 1024)
                .and_then(|_| serde_json::from_slice::<Value>(&bytes).ok())
                .filter(Value::is_object);
            let result = match parsed {
                Some(payload) => pipeline::post_evaluate(&payload).await,
                None => json!({}),
            };
            println!("{result}");
        }
        Commands::Logs {
            command,
            limit,
            decision,
            tool,
            conversation,
            json,
            follow,
        } => match command {
            Some(LogsCommand::Show { id }) => {
                println!("{}", serde_json::to_string_pretty(&audit::show(&id)?)?)
            }
            None => {
                let filter = audit::Filter {
                    limit: limit as usize,
                    decision,
                    tool,
                    conversation,
                };
                if follow {
                    audit::follow(&filter, json).await?;
                } else {
                    audit::print_list(&filter, json)?;
                }
            }
        },
        Commands::Update { version } => upgrade::update(version.as_deref()).await?,
        Commands::Install {
            cli_only,
            desktop_only,
        } => register::register(cli_only, desktop_only)?,
        Commands::Daemon { command } => match command {
            DaemonCommand::Run { idle_timeout } => daemon::run(idle_timeout).await?,
            DaemonCommand::Start => println!("{}", daemon::start().await?),
            DaemonCommand::Flush => {
                let v =
                    daemon::request(&config::socket_path(), &json!({"action": "flush"}), 5).await?;
                let count = v["flushed_count"].as_u64().unwrap_or(0);
                println!("Flushed {count} active reviewer process(es).");
            }
            DaemonCommand::Status { json } => {
                match daemon::request(&config::socket_path(), &json!({"action": "status"}), 3).await
                {
                    Ok(v) if v["status"] == "running" => {
                        if json {
                            println!("{}", serde_json::to_string_pretty(&v)?);
                        } else {
                            let pid = v["pid"].as_u64().unwrap_or(0);
                            let uptime = v["uptime_seconds"].as_u64().unwrap_or(0);
                            let evals = v["evaluations"].as_u64().unwrap_or(0);
                            let active_evals = v["active_evaluations"].as_u64().unwrap_or(0);

                            println!("Approver Daemon: running (PID {pid}, uptime {uptime}s)");
                            println!("Evaluations:     {evals} (active: {active_evals})");
                            println!("Socket:          {}", config::socket_path().display());
                            println!();
                            println!("Tracked Conversations:");

                            if let Some(convs) = v["conversations"].as_array() {
                                if convs.is_empty() {
                                    println!("  (No conversations tracked yet)");
                                } else {
                                    for conv in convs {
                                        let scid = conv["source_cid"].as_str().unwrap_or("-");
                                        let rcid =
                                            conv["reviewer_cid"].as_str().unwrap_or("(none)");
                                        let project = conv["project"].as_str().unwrap_or("(none)");
                                        let state = conv["process_state"].as_str().unwrap_or("-");

                                        println!("- Source CID:   {scid}");
                                        println!("  Reviewer CID: {rcid}");
                                        println!("  Project:      {project}");
                                        println!("  Process:      {state}");
                                        println!();
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        if json {
                            println!(
                                "{}",
                                json!({"status": "stopped", "socket": config::socket_path()})
                            );
                        } else {
                            println!(
                                "Approver Daemon: stopped (socket: {})",
                                config::socket_path().display()
                            );
                        }
                        std::process::exit(1);
                    }
                }
            }
            DaemonCommand::Stop => {
                let v =
                    daemon::request(&config::socket_path(), &json!({"action": "stop"}), 1).await?;
                if v["status"] != "stopping" {
                    bail!("Unexpected stop response: {v}");
                }
                for _ in 0..150 {
                    if !config::socket_path().exists() {
                        use fs2::FileExt;
                        let lock_path = config::socket_path().with_extension("sock.lock");
                        if let Ok(file) = std::fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&lock_path)
                        {
                            if file.try_lock_exclusive().is_ok() {
                                println!("{}", json!({"status": "stopped"}));
                                return Ok(());
                            }
                        } else {
                            println!("{}", json!({"status": "stopped"}));
                            return Ok(());
                        }
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
                bail!("Daemon acknowledged stop but socket still exists");
            }
        },
    }
    Ok(())
}
