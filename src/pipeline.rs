use crate::{audit, config, daemon, parser, reviewer::Assessment};
use anyhow::Result;
use fs2::FileExt;
use regex::Regex;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::LazyLock,
};

/// Check command against hardcoded blacklist patterns.
/// Rejects dangerous destructive actions immediately without LLM review.
pub fn blacklist(command: &str) -> Option<String> {
    static PATTERNS: LazyLock<Vec<Regex>> = LazyLock::new(|| {
        [
            r"(?:^|[;&|\n`$()])\s*rm\s+-[rfRF]*\s+/(?:\*|\s*$)",
            r"(?:^|[;&|\n`$()])\s*rm\s+-[rfRF]*\s+~(?:/.*|\s*$)",
            r"(?:^|[;&|\n`$()])\s*rm\s+-[rfRF]*\s+\$HOME(?:/.*|\s*$)",
            r"(?:^|[;&|\n`$()])\s*rm\s+-[rfRF]*\s+/(?:etc|usr|var|bin|System|boot|sbin|Users|home)(?:/|\s+|$)",
            r"(?:^|[;&|\n`$()])\s*rm\s+-[rfRF]*\s+(?:.*/)?\.git(?:/|\s+|$)",
            r"\bmkfs\b",
            r"\bfdisk\b",
            r"\bdd\s+if=",
            r":\(\)\{\s*:\|:&\s*\};:",
            r"(?:^|[;&|\n`$()])\s*chmod\s+-[rwxRWX0-7]*\s+777\s+/",
        ]
        .iter()
        .map(|s| Regex::new(s).unwrap())
        .collect()
    });
    for cmd in std::iter::once(command.to_string()).chain(parser::commands(command)) {
        for pattern in PATTERNS.iter() {
            if pattern.is_match(&cmd) {
                return Some(format!(
                    "Blocked by hard blacklist: matched pattern '{}'",
                    pattern.as_str()
                ));
            }
        }
    }
    None
}

/// Determine if a tool is safe and read-only.
/// Read-only tools are approved immediately without LLM review.
pub fn read_only(tool: &str) -> bool {
    matches!(
        tool,
        "view_file"
            | "grep_search"
            | "find_by_name"
            | "list_dir"
            | "read_url_content"
            | "search_web"
            | "read_browser_page"
            | "finish"
            | "command_status"
            | "wait"
            | "wait_5_seconds"
    )
}

/// Unified per-conversation state management.
/// Manages circuit breaker thresholds, reviewer conversation IDs, and target project paths.
/// Stored at ~/.gemini/agy-auto-approve/state/<source_cid>.json.
pub struct ConversationState {
    path: PathBuf,
    _lock: fs::File,
    state: Value,
}

/// Backward compatibility alias for ConversationState.
pub type Breaker = ConversationState;

impl ConversationState {
    /// Open or initialize conversation state with exclusive file locking.
    pub fn open(dir: &Path, cid: &str) -> Result<Self> {
        fs::create_dir_all(dir)?;
        let clean_cid: String = cid
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let path = dir.join(format!("{clean_cid}.json"));
        let lock_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path.with_extension("lock"))?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            match lock_file.try_lock_exclusive() {
                Ok(()) => break,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                Err(e) => return Err(e.into()),
            }
        }
        let state = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .filter(Value::is_object)
            .unwrap_or_else(|| {
                json!({
                    "source_cid": cid,
                    "project": "",
                    "reviewer_conversation_id": Value::Null,
                    "consecutive_denials": 0,
                    "history": [],
                    "awaiting_approval": false,
                    "awaiting_step": Value::Null,
                    "last_active": chrono::Utc::now().to_rfc3339(),
                })
            });
        Ok(Self {
            path,
            _lock: lock_file,
            state,
        })
    }

    /// Check if the circuit breaker has tripped.
    /// Trips on:
    /// 1. 3 consecutive denials.
    /// 2. 4 denials in the last 5 evaluation results.
    pub fn tripped(&self) -> Option<String> {
        let count = self.state["consecutive_denials"].as_u64().unwrap_or(0);
        if count >= 3 {
            return Some(format!(
                "Circuit breaker tripped: {count} consecutive denials exceeded threshold (3). Halting loop to prompt user."
            ));
        }
        if let Some(history) = self.state["history"].as_array() {
            let denials = history
                .iter()
                .rev()
                .take(5)
                .filter(|v| **v == "deny")
                .count();
            if history.len() >= 5 && denials >= 4 && history.last() == Some(&json!("deny")) {
                return Some(format!(
                    "Circuit breaker tripped: {denials}/5 denials in recent window. Halting loop to prompt user."
                ));
            }
        }
        None
    }

    /// Record an evaluation decision and update denial counters.
    pub fn record(&mut self, decision: &str) -> Result<()> {
        if decision == "allow" {
            self.state["awaiting_approval"] = false.into();
            self.state["awaiting_step"] = Value::Null;
        }
        self.state["consecutive_denials"] = if decision == "deny" {
            self.state["consecutive_denials"].as_u64().unwrap_or(0) + 1
        } else {
            0
        }
        .into();
        let mut history = self.state["history"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        history.push(decision.into());
        if history.len() > 5 {
            history.drain(..history.len() - 5);
        }
        self.state["history"] = history.into();
        self.state["last_active"] = chrono::Utc::now().to_rfc3339().into();
        self.save()
    }

    /// Mark that this conversation is awaiting explicit user approval after tripping the breaker.
    pub fn mark_force_ask(&mut self, step_idx: Option<u64>) -> Result<()> {
        self.state["awaiting_approval"] = true.into();
        self.state["awaiting_step"] = step_idx.into();
        self.state["last_active"] = chrono::Utc::now().to_rfc3339().into();
        self.save()
    }

    /// Process a completed tool execution from PostToolUse.
    /// If user approved the tool call that was awaiting approval, reset the circuit breaker.
    pub fn on_post_tool_use(&mut self, step_idx: Option<u64>) -> Result<bool> {
        let awaiting = self.state["awaiting_approval"].as_bool().unwrap_or(false);
        if !awaiting {
            return Ok(false);
        }
        let expected_step = self.state["awaiting_step"].as_u64();
        if expected_step.is_some() && step_idx.is_some() && expected_step != step_idx {
            return Ok(false);
        }
        self.state["awaiting_approval"] = false.into();
        self.state["awaiting_step"] = Value::Null;
        self.record("allow")?;
        Ok(true)
    }

    /// Set and persist the reviewer conversation ID.
    pub fn set_reviewer_cid(&mut self, reviewer_cid: &str) -> Result<()> {
        self.state["reviewer_conversation_id"] = reviewer_cid.into();
        self.state["last_active"] = chrono::Utc::now().to_rfc3339().into();
        self.save()
    }

    /// Set and persist the project workspace path.
    pub fn set_project(&mut self, project: &str) -> Result<()> {
        self.state["project"] = project.into();
        self.state["last_active"] = chrono::Utc::now().to_rfc3339().into();
        self.save()
    }

    /// Get the associated reviewer conversation ID if available.
    pub fn reviewer_cid(&self) -> Option<String> {
        self.state["reviewer_conversation_id"]
            .as_str()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
    }

    /// Get the project workspace path.
    pub fn project(&self) -> String {
        self.state["project"].as_str().unwrap_or("").to_string()
    }

    /// Get the source conversation ID.
    pub fn source_cid(&self) -> String {
        self.state["source_cid"]
            .as_str()
            .unwrap_or("default")
            .to_string()
    }

    /// Get consecutive denials count.
    pub fn consecutive_denials(&self) -> u64 {
        self.state["consecutive_denials"].as_u64().unwrap_or(0)
    }

    /// Atomically write current state to disk.
    fn save(&self) -> Result<()> {
        let tmp = self.path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec(&self.state)?)?;
        fs::rename(tmp, &self.path)?;
        Ok(())
    }
}

/// Construct JSON response payload matching Antigravity hook contract.
pub fn result(decision: &str, reason: &str, tool: &str, grants: Option<Vec<String>>) -> Value {
    let tag = match decision {
        "allow" => "ALLOWED",
        "deny" => "DENIED",
        _ => "REVIEW REQUIRED",
    };
    let reason = if reason.trim().starts_with("[agy-auto-approve") {
        reason.trim().into()
    } else {
        format!("[agy-auto-approve: {tag}] {}", reason.trim())
    };
    let dir = config::log_dir();
    if fs::create_dir_all(&dir).is_ok()
        && let Ok(mut f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join("auto-approve.log"))
    {
        let _ = writeln!(
            f,
            "[{}] [{:<5}] tool={} | reason={}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            decision.to_uppercase(),
            tool,
            reason
        );
    }
    if std::env::var("AGY_AUTO_APPROVE_SILENT")
        .unwrap_or_default()
        .is_empty()
    {
        let color = match decision {
            "allow" => 32,
            "deny" => 31,
            _ => 33,
        };
        eprintln!(
            "\x1b[{color}m[agy-auto-approve: {}]\x1b[0m {tool} -> {reason}",
            decision.to_uppercase()
        );
    }
    let mut payload = json!({"decision": decision, "reason": reason});
    if let Some(grants) = grants {
        payload["permissionOverrides"] = grants.into();
    }
    payload
}

/// Primary PreToolUse hook entry point.
pub async fn evaluate(payload: &Value) -> Value {
    let id = audit::request_id();
    let started = std::time::Instant::now();
    audit::record(&id, "hook_input", json!({"input": payload}));
    let mut stage = "reviewer";
    let output = evaluate_inner(payload, &id, &mut stage).await;
    audit::record(
        &id,
        "hook_result",
        json!({
            "tool": payload["toolCall"]["name"],
            "command": payload["toolCall"]["args"]["CommandLine"],
            "cwd": payload["toolCall"]["args"]["Cwd"],
            "hook_pid": std::process::id(),
            "conversation_id": conversation_id(payload),
            "output": output,
            "stage": stage,
            "duration_ms": started.elapsed().as_millis(),
        }),
    );
    output
}

/// Extract conversation ID from payload with fallback to "default".
fn conversation_id(payload: &Value) -> &str {
    payload["conversationId"]
        .as_str()
        .filter(|s| !s.is_empty())
        .or(payload["conversation_id"].as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("default")
}

/// Extract project workspace path from payload.
fn extract_project(payload: &Value) -> String {
    if let Some(ws) = payload["workspacePaths"].as_array()
        && let Some(first) = ws.first().and_then(Value::as_str)
        && !first.is_empty()
    {
        return first.to_string();
    }
    if let Some(cwd) = payload["toolCall"]["args"]["Cwd"].as_str()
        && !cwd.is_empty()
    {
        return cwd.to_string();
    }
    String::new()
}

/// Inner evaluation pipeline executing whitelist, blacklist, circuit breaker, and daemon review.
async fn evaluate_inner(payload: &Value, id: &str, stage: &mut &'static str) -> Value {
    let tool = payload["toolCall"]["name"].as_str().unwrap_or("");
    let args = &payload["toolCall"]["args"];

    // Prevent recursive review of internal reviewer processes.
    if std::env::var_os("AGY_AUTO_APPROVE_INTERNAL").is_some() {
        *stage = "internal";
        return result(
            "allow",
            "Internal reviewer process automatically approved.",
            tool,
            Some(vec![]),
        );
    }

    if read_only(tool) {
        *stage = "whitelist";
        return result(
            "allow",
            "Read-only tool automatically approved.",
            tool,
            Some(vec![]),
        );
    }

    if tool == "manage_task" {
        let action = args["Action"].as_str().unwrap_or("");
        if action == "list" || action == "status" {
            *stage = "whitelist";
            return result(
                "allow",
                "Read-only task inspection automatically approved.",
                tool,
                Some(vec![]),
            );
        }
    }
    if tool == "run_command"
        && let Some(reason) = blacklist(args["CommandLine"].as_str().unwrap_or(""))
    {
        *stage = "blacklist";
        return result("deny", &reason, tool, None);
    }
    let cid = conversation_id(payload);
    let mut state = match ConversationState::open(&config::state_dir(), cid) {
        Ok(s) => s,
        Err(e) => {
            *stage = "state_error";
            return result(
                "deny",
                &format!("Fail-closed: cannot open conversation state: {e}"),
                tool,
                None,
            );
        }
    };
    let project = extract_project(payload);
    if !project.is_empty() && state.project().is_empty() {
        let _ = state.set_project(&project);
    }
    if let Some(reason) = state.tripped() {
        *stage = "circuit_breaker";
        let step_idx = payload["stepIdx"].as_u64();
        if let Err(e) = state.mark_force_ask(step_idx) {
            *stage = "state_error";
            return result(
                "deny",
                &format!("Fail-closed: cannot persist circuit breaker state: {e}"),
                tool,
                None,
            );
        }
        return result("force_ask", &reason, tool, None);
    }
    let assessment = match daemon::review_traced(payload, id).await {
        Ok(a) => a,
        Err(e) => {
            *stage = "reviewer_error";
            Assessment::deny(format!("Approver daemon is unavailable: {e}"))
        }
    };
    audit::record(id, "assessment", json!({"assessment": assessment}));
    if assessment.error_stage.is_some() {
        *stage = "reviewer_error";
    }
    if let Some(reviewer_cid) = &assessment.reviewer_cid {
        let _ = state.set_reviewer_cid(reviewer_cid);
    }
    if let Err(e) = state.record(&assessment.outcome) {
        *stage = "state_error";
        return result(
            "deny",
            &format!("Fail-closed: cannot persist evaluation record: {e}"),
            tool,
            None,
        );
    }
    let grants = (assessment.outcome == "allow").then(|| parser::overrides(tool, args));
    result(&assessment.outcome, &assessment.rationale, tool, grants)
}

/// Handle PostToolUse hook events.
/// Checks if the completed tool execution corresponds to a step that was awaiting user approval.
/// If user explicitly approved, resets consecutive denials.
/// Always returns an empty JSON object `{}`.
pub async fn post_evaluate(payload: &Value) -> Value {
    let id = audit::request_id();
    let cid = conversation_id(payload);
    let step_idx = payload["stepIdx"].as_u64();
    audit::record(
        &id,
        "post_hook_input",
        json!({
            "conversation_id": cid,
            "step_idx": step_idx,
            "error": payload.get("error"),
        }),
    );
    if let Ok(mut state) = ConversationState::open(&config::state_dir(), cid)
        && let Ok(true) = state.on_post_tool_use(step_idx)
    {
        audit::record(
            &id,
            "circuit_breaker_reset",
            json!({
                "conversation_id": cid,
                "step_idx": step_idx,
                "reason": "User approved tool execution detected during PostToolUse",
            }),
        );
        let dir = config::log_dir();
        if fs::create_dir_all(&dir).is_ok()
            && let Ok(mut f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("auto-approve.log"))
        {
            let _ = writeln!(
                f,
                "[{}] [RESET] cid={} step={:?} | Circuit breaker reset following user approval in PostToolUse",
                chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
                cid,
                step_idx,
            );
        }
    }
    json!({})
}
