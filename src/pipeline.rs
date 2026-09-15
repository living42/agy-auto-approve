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

/// Normalize path components lexically without accessing the filesystem.
///
/// Responsibility:
/// Resolves `.` and `..` components to prevent directory traversal escapes.
///
/// How it works:
/// Iterates over path components: ignores `CurDir`, pops on `ParentDir`, and pushes normal components.
pub fn normalize_path(path: &Path) -> PathBuf {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                components.pop();
            }
            c => components.push(c),
        }
    }
    components.into_iter().collect()
}

/// Canonicalize an existing path or the longest existing ancestor path.
///
/// Responsibility:
/// Resolves symlinks (such as macOS `/var` -> `/private/var`) for both existing
/// and not-yet-created files.
///
/// How it works:
/// If the path exists on disk, returns `path.canonicalize()`. Otherwise, walks up
/// parent directories until an existing ancestor directory is found, canonicalizes
/// that ancestor, and appends the non-existing child path components.
pub fn canonicalize_with_ancestor(path: &Path) -> PathBuf {
    if let Ok(c) = path.canonicalize() {
        return c;
    }
    let mut ancestor = path;
    let mut tail = Vec::new();
    while let Some(parent) = ancestor.parent() {
        if let Some(file_name) = ancestor.file_name() {
            tail.push(file_name);
        }
        if let Ok(canon_parent) = parent.canonicalize() {
            let mut res = canon_parent;
            for part in tail.into_iter().rev() {
                res.push(part);
            }
            return res;
        }
        ancestor = parent;
    }
    path.to_path_buf()
}

/// Determine whether `target` is contained within `base` directory.
///
/// Responsibility:
/// Safely verifies that a file path resides inside an allowed directory root.
///
/// How it works:
/// 1. Checks if lexical `normalize_path(target)` starts with `normalize_path(base)`.
/// 2. If false, resolves symlinks using `canonicalize_with_ancestor` and checks
///    if canonicalized target starts with canonicalized base.
pub fn is_subpath(target: &Path, base: &Path) -> bool {
    let norm_target = normalize_path(target);
    let norm_base = normalize_path(base);
    if norm_target.starts_with(&norm_base) {
        return true;
    }
    if let Ok(canon_base) = base.canonicalize() {
        let canon_target = canonicalize_with_ancestor(&norm_target);
        if canon_target.starts_with(&canon_base) {
            return true;
        }
    }
    false
}

/// Determine whether a tool call is an authorized file edit within the workspace.
///
/// Responsibility:
/// Identifies file-modifying tools (`write_to_file`, `replace_file_content`, `edit_file`, `apply_patch`)
/// whose target file resides inside the active workspace or artifact directories.
///
/// How it works:
/// 1. Checks if the tool name matches file editing tools.
/// 2. Extracts the target file path from tool arguments.
/// 3. Rejects any target path targeting `.git` metadata or hooks.
/// 4. Resolves relative target paths against workspace roots.
/// 5. Verifies the target path is inside `workspacePaths`, `artifactDirectoryPath`, or `extract_project`.
pub fn is_workspace_edit(payload: &Value) -> bool {
    let tool = payload["toolCall"]["name"].as_str().unwrap_or("");
    if !matches!(
        tool,
        "write_to_file" | "replace_file_content" | "edit_file" | "apply_patch"
    ) {
        return false;
    }

    let args = &payload["toolCall"]["args"];
    let target_str = args["TargetFile"]
        .as_str()
        .or_else(|| args["target_file"].as_str())
        .or_else(|| args["FilePath"].as_str())
        .or_else(|| args["file_path"].as_str())
        .or_else(|| args["Path"].as_str())
        .or_else(|| args["path"].as_str())
        .unwrap_or("")
        .trim();

    if target_str.is_empty() {
        return false;
    }

    let target_path = Path::new(target_str);
    let norm_target = normalize_path(target_path);

    // Never auto-approve direct modifications to .git metadata or hooks.
    if norm_target.components().any(|c| c.as_os_str() == ".git") {
        return false;
    }

    let mut roots = Vec::new();
    if let Some(ws) = payload["workspacePaths"].as_array() {
        for p in ws
            .iter()
            .filter_map(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            roots.push(PathBuf::from(p));
        }
    }
    if let Some(artifact_dir) = payload["artifactDirectoryPath"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        roots.push(PathBuf::from(artifact_dir));
    }
    let project = extract_project(payload);
    if !project.is_empty() {
        let p = PathBuf::from(project);
        if !roots.contains(&p) {
            roots.push(p);
        }
    }

    for root in &roots {
        let full_target = if target_path.is_relative() {
            root.join(target_path)
        } else {
            target_path.to_path_buf()
        };
        if is_subpath(&full_target, root) {
            return true;
        }
    }

    false
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
    /// Trips when consecutive or windowed denials exceed configured thresholds.
    pub fn tripped(&self) -> Option<String> {
        let (max_consecutive, window, threshold) = config::circuit_breaker_limits();
        let count = self.state["consecutive_denials"].as_u64().unwrap_or(0);
        if count >= max_consecutive {
            return Some(format!(
                "Circuit breaker tripped: {count} consecutive denials exceeded threshold ({max_consecutive}). Halting loop to prompt user."
            ));
        }
        if let Some(history) = self.state["history"].as_array() {
            let denials = history
                .iter()
                .rev()
                .take(window)
                .filter(|v| **v == "deny")
                .count();
            if history.len() >= window && denials >= threshold && history.last() == Some(&json!("deny")) {
                return Some(format!(
                    "Circuit breaker tripped: {denials}/{window} denials in recent window. Halting loop to prompt user."
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
/// Output format: `{"decision": decision, "reason": reason}`.
pub fn result(decision: &str, reason: &str, tool: &str) -> Value {
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
    json!({"decision": decision, "reason": reason})
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
        );
    }

    // Evaluate configured Antigravity permission rules (Deny > Allow).
    if let Some(outcome) = config::check_permissions(tool, args) {
        match outcome {
            config::PermissionOutcome::Deny(reason) => {
                *stage = "permission_deny";
                return result("deny", &reason, tool);
            }
            config::PermissionOutcome::Allow(reason) => {
                *stage = "permission_allow";
                return result("allow", &reason, tool);
            }
        }
    }

    if read_only(tool) {
        *stage = "whitelist";
        return result("allow", "Read-only tool automatically approved.", tool);
    }

    if tool == "manage_task" {
        let action = args["Action"].as_str().unwrap_or("");
        if action == "list" || action == "status" {
            *stage = "whitelist";
            return result(
                "allow",
                "Read-only task inspection automatically approved.",
                tool,
            );
        }
    }

    if is_workspace_edit(payload) {
        *stage = "whitelist";
        return result(
            "allow",
            "Workspace file modification automatically approved.",
            tool,
        );
    }

    if tool == "run_command"
        && let Some(reason) = blacklist(args["CommandLine"].as_str().unwrap_or(""))
    {
        *stage = "blacklist";
        return result("deny", &reason, tool);
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
            );
        }
        return result("force_ask", &reason, tool);
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
        );
    }
    result(&assessment.outcome, &assessment.rationale, tool)
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
