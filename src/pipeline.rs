use crate::{audit, config, daemon, reviewer::Assessment};
use anyhow::Result;
use fs2::FileExt;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

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

/// Target file or directory operation kind.
///
/// Responsibility:
/// Identifies whether an operation reads or modifies a file or directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOpKind {
    Read,
    Write,
}

/// Extract all workspace roots from payload.
///
/// Responsibility:
/// Collects all valid workspace roots, artifact directories, and project paths.
///
/// How it works:
/// Extracts paths from `workspacePaths`, `artifactDirectoryPath`, and `extract_project`.
pub fn extract_workspace_roots(payload: &Value) -> Vec<PathBuf> {
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
    roots
}

/// Extract file operation kind and target path from tool call payload.
///
/// Responsibility:
/// Detects file-reading and file-writing tools and resolves their target path argument.
///
/// How it works:
/// 1. Identifies read tools (`read_file`, `view_file`, `grep_search`, `find_by_name`, `list_dir`).
/// 2. Identifies write tools (`write_file`, `write_to_file`, `replace_file_content`, `edit_file`, `apply_patch`).
/// 3. Extracts target path string from tool arguments.
pub fn extract_file_op(payload: &Value) -> Option<(FileOpKind, PathBuf)> {
    let tool = payload["toolCall"]["name"].as_str().unwrap_or("");
    let args = &payload["toolCall"]["args"];

    let is_read = matches!(
        tool,
        "read_file" | "view_file" | "grep_search" | "find_by_name" | "list_dir"
    );
    let is_write = matches!(
        tool,
        "write_file" | "write_to_file" | "replace_file_content" | "edit_file" | "apply_patch"
    );

    if !is_read && !is_write {
        return None;
    }

    let target_str = if is_read {
        args["AbsolutePath"]
            .as_str()
            .or_else(|| args["SearchPath"].as_str())
            .or_else(|| args["DirectoryPath"].as_str())
            .or_else(|| args["SearchDirectory"].as_str())
            .or_else(|| args["path"].as_str())
            .or_else(|| args["file_path"].as_str())
            .or_else(|| args["FilePath"].as_str())
            .or_else(|| args["TargetFile"].as_str())
            .or_else(|| args["target_file"].as_str())
    } else {
        args["TargetFile"]
            .as_str()
            .or_else(|| args["target_file"].as_str())
            .or_else(|| args["FilePath"].as_str())
            .or_else(|| args["file_path"].as_str())
            .or_else(|| args["Path"].as_str())
            .or_else(|| args["path"].as_str())
    }?;

    let trimmed = target_str.trim();
    if trimmed.is_empty() {
        return None;
    }

    let kind = if is_read {
        FileOpKind::Read
    } else {
        FileOpKind::Write
    };
    Some((kind, PathBuf::from(trimmed)))
}

/// Determine whether a target path is under any of the given workspace roots.
///
/// Responsibility:
/// Validates that target path stays within permitted workspace boundaries.
///
/// How it works:
/// 1. Resolves relative target paths against workspace roots.
/// 2. Verifies `is_subpath` to prevent path traversal escapes.
pub fn is_path_under_workspace(target_path: &Path, roots: &[PathBuf]) -> bool {
    for root in roots {
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

/// Determine whether a tool call is an authorized file operation under the workspace.
///
/// Responsibility:
/// Automatically approves read_file and write_file operations under workspace roots by default.
///
/// How it works:
/// 1. Extracts operation kind (Read or Write) and target path.
/// 2. For write operations: blocks direct modifications to .git metadata or hooks.
/// 3. Verifies that the target path resides within workspace roots.
pub fn is_workspace_file_op(payload: &Value) -> bool {
    let Some((kind, target_path)) = extract_file_op(payload) else {
        return false;
    };

    let norm_target = normalize_path(&target_path);

    // Write operations must not modify .git metadata or hooks by default.
    if kind == FileOpKind::Write && norm_target.components().any(|c| c.as_os_str() == ".git") {
        return false;
    }

    let roots = extract_workspace_roots(payload);
    is_path_under_workspace(&target_path, &roots)
}

/// Backward compatibility helper for workspace write operations.
pub fn is_workspace_edit(payload: &Value) -> bool {
    match extract_file_op(payload) {
        Some((FileOpKind::Write, _)) => is_workspace_file_op(payload),
        _ => false,
    }
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
            if history.len() >= window
                && denials >= threshold
                && history.last() == Some(&json!("deny"))
            {
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

/// Inner evaluation pipeline executing permission rules, default workspace operations, circuit breaker, and daemon review.
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

    // By default, read_file and write_file operations under workspace are allowed.
    if is_workspace_file_op(payload) {
        *stage = "workspace";
        return result(
            "allow",
            "Workspace file operation automatically approved by default.",
            tool,
        );
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
