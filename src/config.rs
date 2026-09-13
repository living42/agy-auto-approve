use std::{env, fs, path::PathBuf};

/// Get the current user home directory from the HOME environment variable.
pub fn home() -> PathBuf {
    env::var_os("HOME")
        .map(PathBuf::from)
        .expect("HOME must be set")
}

/// Base root directory for all agy-auto-approve data, logs, state, and sockets.
/// Defaults to ~/.gemini/agy-auto-approve.
/// Can be overridden via AGY_AUTO_APPROVE_DIR or AGY_AUTO_APPROVE_LOG_DIR.
pub fn base_dir() -> PathBuf {
    env::var_os("AGY_AUTO_APPROVE_DIR")
        .or_else(|| env::var_os("AGY_AUTO_APPROVE_LOG_DIR"))
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home().join(".gemini/agy-auto-approve"))
}

/// Directory where log files (auto-approve.log, approvals.jsonl) are written.
/// Maps directly to base_dir().
pub fn log_dir() -> PathBuf {
    base_dir()
}

/// Directory where per-conversation state files (<source_cid>.json) are stored.
/// Also serves as the current working directory (cwd) for background reviewer processes.
/// Defaults to ~/.gemini/agy-auto-approve/state.
/// Can be overridden via AGY_APPROVER_STATE_DIR.
pub fn state_dir() -> PathBuf {
    env::var_os("AGY_APPROVER_STATE_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir().join("state"))
}

/// Path to the Unix domain socket used for IPC communication with the daemon.
/// Defaults to ~/.gemini/agy-auto-approve/approver.sock.
/// Can be overridden via AGY_APPROVER_SOCKET.
pub fn socket_path() -> PathBuf {
    env::var_os("AGY_APPROVER_SOCKET")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| base_dir().join("approver.sock"))
}

/// Resolve the executable path for the agy CLI binary.
/// Lookup order:
/// 1. AGY_BIN environment variable if set.
/// 2. ~/.local/bin/agy
/// 3. ~/.gemini/antigravity-cli/bin/agy
/// 4. Iteration over directories in PATH.
/// 5. Fallback to "agy".
pub fn agy_bin() -> PathBuf {
    if let Some(explicit) = env::var_os("AGY_BIN").filter(|s| !s.is_empty()) {
        return PathBuf::from(explicit);
    }
    for candidate in [
        home().join(".local/bin/agy"),
        home().join(".gemini/antigravity-cli/bin/agy"),
    ] {
        if candidate.is_file() {
            return candidate;
        }
    }
    if let Ok(search_path) = env::var("PATH") {
        for dir in env::split_paths(&search_path) {
            let candidate = dir.join("agy");
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from("agy")
}

/// Read configuration setting from environment variables or custom configuration files.
pub fn setting(name: &str, default: &str) -> String {
    if let Ok(value) = env::var(format!("AGY_AUTO_APPROVE_{}", name.to_uppercase()))
        && !value.is_empty()
    {
        return value;
    }
    for path in [
        PathBuf::from(format!(".agents/agy-auto-approve-{name}.txt")),
        home().join(format!(".gemini/config/agy-auto-approve-{name}.txt")),
    ] {
        if let Ok(value) = fs::read_to_string(path) {
            if name == "prompt" {
                return value;
            }
            if !value.trim().is_empty() {
                return value.trim().into();
            }
        }
    }
    default.into()
}

/// Return evaluator system prompt text.
pub fn prompt() -> String {
    setting("prompt", include_str!("prompt.txt"))
}

/// Return configured evaluation model and reasoning effort.
pub fn model_and_effort() -> (String, String) {
    (
        setting("model", "gemini-3.7-flash"),
        setting("effort", "medium"),
    )
}
