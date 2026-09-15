use crate::parser;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, RwLock},
    time::SystemTime,
};

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

/// Permission action type in Antigravity specification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionAction {
    ReadFile,
    WriteFile,
    Command,
    Unsandboxed,
    ReadUrl,
    ExecuteUrl,
    Tool(String),
}

/// Internal matcher for permission targets.
#[derive(Debug, Clone)]
pub enum TargetMatcher {
    Wildcard,
    Regex(Regex),
    Path { path: PathBuf, recursive: bool },
    UrlDomain(String),
    ToolName(String),
}

/// Single permission rule matching an action and target.
///
/// Responsibility:
/// Represents a parsed rule like `command(git*)` or `read_file(/path/*)`.
///
/// How it works:
/// Parses `action(target)` syntax. Evaluates against incoming tool calls.
#[derive(Debug, Clone)]
pub struct PermissionRule {
    pub raw: String,
    pub action: PermissionAction,
    pub matcher: TargetMatcher,
}

impl Serialize for PermissionRule {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for PermissionRule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        PermissionRule::parse(&s).map_err(serde::de::Error::custom)
    }
}

impl PermissionRule {
    /// Parse a rule string in Antigravity syntax or fallback format.
    ///
    /// Responsibility:
    /// Converts text into a structured permission rule.
    ///
    /// How it works:
    /// Detects `action(target)`. Converts wildcards and regexes.
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err("Permission rule string is empty".to_string());
        }

        // Check for Antigravity syntax: action(target)
        if let Some(open) = trimmed.find('(')
            && trimmed.ends_with(')')
        {
            let action_name = trimmed[..open].trim();
            let target = trimmed[open + 1..trimmed.len() - 1].trim();
            return Self::build_rule(trimmed, action_name, target);
        }

        // Fallback for bare strings without action(...) wrapper.
        if trimmed.starts_with('/') || trimmed.starts_with("~/") || trimmed.starts_with("./") {
            Self::build_rule(trimmed, "read_file", trimmed)
        } else if trimmed == "view_file"
            || trimmed == "read_url_content"
            || trimmed == "search_web"
            || trimmed == "read_browser_page"
            || trimmed == "finish"
            || trimmed == "list_dir"
            || trimmed == "grep_search"
            || trimmed == "find_by_name"
        {
            Self::build_rule(trimmed, "tool", trimmed)
        } else {
            Self::build_rule(trimmed, "command", trimmed)
        }
    }

    /// Build a rule from action name and target content.
    fn build_rule(raw: &str, action_str: &str, target_str: &str) -> Result<Self, String> {
        let action = match action_str {
            "read_file" => PermissionAction::ReadFile,
            "write_file" => PermissionAction::WriteFile,
            "command" => PermissionAction::Command,
            "unsandboxed" => PermissionAction::Unsandboxed,
            "read_url" => PermissionAction::ReadUrl,
            "execute_url" => PermissionAction::ExecuteUrl,
            "tool" => PermissionAction::Tool(target_str.to_string()),
            other => PermissionAction::Tool(other.to_string()),
        };

        let matcher = if target_str == "*" {
            TargetMatcher::Wildcard
        } else if let Some(re_pattern) = target_str.strip_prefix("regex:") {
            let re = Regex::new(re_pattern)
                .map_err(|e| format!("Invalid regex in rule '{raw}': {e}"))?;
            TargetMatcher::Regex(re)
        } else {
            match action {
                PermissionAction::ReadFile | PermissionAction::WriteFile => {
                    let (clean_path, recursive) =
                        if let Some(prefix) = target_str.strip_suffix("/**") {
                            (prefix, true)
                        } else if let Some(prefix) = target_str.strip_suffix("/*") {
                            (prefix, true)
                        } else {
                            (target_str, false)
                        };

                    let expanded = if clean_path == "~" {
                        home()
                    } else if let Some(rest) = clean_path.strip_prefix("~/") {
                        home().join(rest)
                    } else {
                        PathBuf::from(clean_path)
                    };
                    TargetMatcher::Path {
                        path: expanded,
                        recursive,
                    }
                }
                PermissionAction::Command | PermissionAction::Unsandboxed => {
                    let regex_str = build_command_regex(target_str);
                    let re = Regex::new(&regex_str)
                        .map_err(|e| format!("Invalid command pattern in rule '{raw}': {e}"))?;
                    TargetMatcher::Regex(re)
                }
                PermissionAction::ReadUrl | PermissionAction::ExecuteUrl => {
                    TargetMatcher::UrlDomain(target_str.to_string())
                }
                PermissionAction::Tool(_) => TargetMatcher::ToolName(target_str.to_string()),
            }
        };

        Ok(Self {
            raw: raw.to_string(),
            action,
            matcher,
        })
    }

    /// Check if this rule matches a single command string.
    pub fn matches_single_command(&self, cmd: &str) -> bool {
        match &self.action {
            PermissionAction::Command | PermissionAction::Unsandboxed => {}
            _ => return false,
        }

        match &self.matcher {
            TargetMatcher::Wildcard => true,
            TargetMatcher::Regex(re) => re.is_match(cmd.trim()),
            _ => false,
        }
    }

    /// Check if this rule matches a file path operation.
    pub fn matches_path(&self, target_path: &Path, is_write: bool) -> bool {
        match self.action {
            PermissionAction::WriteFile => {}
            // Write permission implicitly includes read permission.
            PermissionAction::ReadFile if !is_write => {}
            _ => return false,
        }

        match &self.matcher {
            TargetMatcher::Wildcard => true,
            TargetMatcher::Regex(re) => re.is_match(&target_path.to_string_lossy()),
            TargetMatcher::Path { path, recursive } => {
                let norm_target = normalize_lexical(target_path);
                let norm_base = normalize_lexical(path);
                if *recursive {
                    norm_target.starts_with(&norm_base)
                } else {
                    norm_target == norm_base || norm_target.starts_with(&norm_base)
                }
            }
            _ => false,
        }
    }

    /// Check if this rule matches a URL operation.
    pub fn matches_url(&self, url: &str) -> bool {
        match self.action {
            PermissionAction::ReadUrl | PermissionAction::ExecuteUrl => {}
            _ => return false,
        }

        match &self.matcher {
            TargetMatcher::Wildcard => true,
            TargetMatcher::Regex(re) => re.is_match(url),
            TargetMatcher::UrlDomain(domain) => url.contains(domain),
            _ => false,
        }
    }

    /// Check if this rule matches a generic tool call name.
    pub fn matches_tool_name(&self, tool: &str) -> bool {
        match &self.action {
            PermissionAction::Tool(name) => name == "*" || name == tool,
            _ => false,
        }
    }
}

/// Convert a shell command glob pattern into a regular expression.
fn build_command_regex(pattern: &str) -> String {
    if pattern.starts_with('^') {
        return pattern.to_string();
    }
    let mut regex = String::from("^");
    let has_wildcard = pattern.contains('*') || pattern.contains('?');

    for c in pattern.chars() {
        match c {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '[' | ']' | '{' | '}' | '^' | '$' | '|' | '\\' => {
                regex.push('\\');
                regex.push(c);
            }
            _ => regex.push(c),
        }
    }

    if !has_wildcard {
        regex.push_str(r"(\s.*)?$");
    } else {
        regex.push('$');
    }
    regex
}

/// Lexical path normalization without disk access.
fn normalize_lexical(path: &Path) -> PathBuf {
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

/// Permissive list of permission rules.
///
/// Responsibility:
/// Supports deserializing rules from a list of strings or structured maps.
#[derive(Debug, Clone, Default)]
pub struct RuleList(pub Vec<PermissionRule>);

impl Serialize for RuleList {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RuleList {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        let mut rules = Vec::new();

        match value {
            Value::Array(items) => {
                for item in items {
                    if let Some(s) = item.as_str()
                        && let Ok(rule) = PermissionRule::parse(s)
                    {
                        rules.push(rule);
                    }
                }
            }
            Value::Object(map) => {
                if let Some(tools) = map.get("tools").and_then(Value::as_array) {
                    for item in tools {
                        if let Some(s) = item.as_str()
                            && let Ok(rule) = PermissionRule::parse(s)
                        {
                            rules.push(rule);
                        }
                    }
                }
                if let Some(commands) = map.get("commands").and_then(Value::as_array) {
                    for item in commands {
                        if let Some(s) = item.as_str()
                            && let Ok(rule) = PermissionRule::parse(s)
                        {
                            rules.push(rule);
                        }
                    }
                }
            }
            Value::String(s) => {
                if let Ok(rule) = PermissionRule::parse(&s) {
                    rules.push(rule);
                }
            }
            _ => {}
        }

        Ok(RuleList(rules))
    }
}

/// Circuit breaker configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_cb_consecutive")]
    pub max_consecutive_denials: u64,
    #[serde(default = "default_cb_window")]
    pub recent_denials_window: usize,
    #[serde(default = "default_cb_threshold")]
    pub recent_denials_threshold: usize,
}

fn default_cb_consecutive() -> u64 {
    3
}

fn default_cb_window() -> usize {
    5
}

fn default_cb_threshold() -> usize {
    4
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            max_consecutive_denials: default_cb_consecutive(),
            recent_denials_window: default_cb_window(),
            recent_denials_threshold: default_cb_threshold(),
        }
    }
}

/// Daemon timeouts configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_daemon_idle_timeout")]
    pub idle_timeout: u64,
    #[serde(default = "default_daemon_reclaim_timeout")]
    pub worker_reclaim_timeout: u64,
}

fn default_daemon_idle_timeout() -> u64 {
    1800
}

fn default_daemon_reclaim_timeout() -> u64 {
    600
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            idle_timeout: default_daemon_idle_timeout(),
            worker_reclaim_timeout: default_daemon_reclaim_timeout(),
        }
    }
}

/// Optional nested permissions block in YAML.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermissionsBlock {
    #[serde(default, alias = "deny_list", alias = "denylist", alias = "blacklist")]
    pub deny: RuleList,
    #[serde(
        default,
        alias = "allow_list",
        alias = "allowlist",
        alias = "whitelist"
    )]
    pub allow: RuleList,
}

fn default_model() -> String {
    "gemini-3.7-flash".to_string()
}

fn default_effort() -> String {
    "medium".to_string()
}

fn default_timeout() -> u64 {
    120
}

/// Full configuration struct loaded from YAML or environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default = "default_model", alias = "module")]
    pub model: String,

    #[serde(
        default = "default_effort",
        alias = "thinking_effort",
        alias = "thinking effort"
    )]
    pub effort: String,

    #[serde(
        default = "default_timeout",
        alias = "evaluate_timeout",
        alias = "evalute_timeout",
        alias = "eval_timeout"
    )]
    pub timeout: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_file: Option<PathBuf>,

    #[serde(default, alias = "deny_list", alias = "denylist", alias = "blacklist")]
    pub deny: RuleList,

    #[serde(
        default,
        alias = "allow_list",
        alias = "allowlist",
        alias = "whitelist"
    )]
    pub allow: RuleList,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permissions: Option<PermissionsBlock>,

    #[serde(default)]
    pub circuit_breaker: CircuitBreakerConfig,

    #[serde(default)]
    pub daemon: DaemonConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            model: default_model(),
            effort: default_effort(),
            timeout: default_timeout(),
            prompt: None,
            prompt_file: None,
            deny: RuleList::default(),
            allow: RuleList::default(),
            permissions: None,
            circuit_breaker: CircuitBreakerConfig::default(),
            daemon: DaemonConfig::default(),
        }
    }
}

/// Internal cached configuration structure.
struct CachedConfig {
    path: Option<PathBuf>,
    mtime: Option<SystemTime>,
    config: Arc<Config>,
}

static CONFIG_CACHE: LazyLock<RwLock<Option<CachedConfig>>> = LazyLock::new(|| RwLock::new(None));

/// Find the active configuration file according to discovery precedence.
///
/// Priority order:
/// 1. AGY_AUTO_APPROVE_CONFIG
/// 2. Workspace `.agents/agy-auto-approve.yaml`
/// 3. User config `~/.gemini/agy-auto-approve/config.yaml`
/// 4. Legacy global config `~/.gemini/config/agy-auto-approve.yaml`
pub fn find_config_file() -> Option<PathBuf> {
    if let Some(explicit) = env::var_os("AGY_AUTO_APPROVE_CONFIG").filter(|s| !s.is_empty()) {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some(p);
        }
    }

    [
        PathBuf::from(".agents/agy-auto-approve.yaml"),
        PathBuf::from(".agents/agy-auto-approve.yml"),
        home().join(".gemini/agy-auto-approve/config.yaml"),
        home().join(".gemini/agy-auto-approve/config.yml"),
        home().join(".gemini/config/agy-auto-approve.yaml"),
        home().join(".gemini/config/agy-auto-approve.yml"),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

/// Return path of active configuration file if one exists.
pub fn active_config_path() -> Option<PathBuf> {
    find_config_file()
}

/// Retrieve the current active configuration with automatic reload on file changes.
pub fn current() -> Arc<Config> {
    let resolved_path = find_config_file();
    let current_mtime = resolved_path
        .as_ref()
        .and_then(|p| fs::metadata(p).ok())
        .and_then(|m| m.modified().ok());

    {
        let cache = CONFIG_CACHE.read().unwrap();
        if let Some(ref cached) = *cache
            && cached.path == resolved_path
            && cached.mtime == current_mtime
        {
            return cached.config.clone();
        }
    }

    let mut config = if let Some(ref path) = resolved_path {
        match fs::read_to_string(path) {
            Ok(content) => match serde_yaml::from_str::<Config>(&content) {
                Ok(c) => c,
                Err(err) => {
                    eprintln!(
                        "\x1b[33m[agy-auto-approve: CONFIG_WARNING]\x1b[0m Failed to parse {}: {err}. Using defaults.",
                        path.display()
                    );
                    Config::default()
                }
            },
            Err(_) => Config::default(),
        }
    } else {
        Config::default()
    };

    // Merge nested permissions block if present.
    if let Some(ref mut perms) = config.permissions {
        config.deny.0.append(&mut perms.deny.0);
        config.allow.0.append(&mut perms.allow.0);
    }

    // Apply environment variable overrides (highest precedence for runtime parameters).
    if let Ok(model) = env::var("AGY_AUTO_APPROVE_MODEL")
        && !model.is_empty()
    {
        config.model = model;
    }
    if let Ok(effort) = env::var("AGY_AUTO_APPROVE_EFFORT")
        && !effort.is_empty()
    {
        config.effort = effort;
    }
    if let Ok(timeout) = env::var("AGY_AUTO_APPROVE_TIMEOUT")
        && !timeout.is_empty()
        && let Ok(val) = timeout.parse::<u64>()
    {
        config.timeout = val;
    }
    if let Ok(prompt) = env::var("AGY_AUTO_APPROVE_PROMPT")
        && !prompt.is_empty()
    {
        config.prompt = Some(prompt);
    }

    // Check custom prompt file if specified.
    if config.prompt.is_none()
        && let Some(ref prompt_file) = config.prompt_file
        && let Ok(content) = fs::read_to_string(prompt_file)
    {
        config.prompt = Some(content);
    }

    // Check legacy individual text files if settings were not explicitly configured.
    if config.prompt.is_none() {
        for path in [
            PathBuf::from(".agents/agy-auto-approve-prompt.txt"),
            home().join(".gemini/config/agy-auto-approve-prompt.txt"),
        ] {
            if let Ok(val) = fs::read_to_string(path) {
                config.prompt = Some(val);
                break;
            }
        }
    }

    let arc = Arc::new(config);
    let mut cache = CONFIG_CACHE.write().unwrap();
    *cache = Some(CachedConfig {
        path: resolved_path,
        mtime: current_mtime,
        config: arc.clone(),
    });

    arc
}

/// Reset the configuration cache. Used in tests.
pub fn reset_cache() {
    let mut cache = CONFIG_CACHE.write().unwrap();
    *cache = None;
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
    if let Ok(value) = env::var("AGY_AUTO_APPROVE_PROMPT")
        && !value.is_empty()
    {
        return value;
    }
    for path in [
        PathBuf::from(".agents/agy-auto-approve-prompt.txt"),
        home().join(".gemini/config/agy-auto-approve-prompt.txt"),
    ] {
        if let Ok(value) = fs::read_to_string(path) {
            return value;
        }
    }
    current()
        .prompt
        .clone()
        .unwrap_or_else(|| include_str!("prompt.txt").to_string())
}

/// Return configured evaluation model and reasoning effort.
pub fn model_and_effort() -> (String, String) {
    let c = current();
    (setting("model", &c.model), setting("effort", &c.effort))
}

/// Return evaluation timeout in seconds for reviewer LLM evaluations.
pub fn eval_timeout() -> u64 {
    let c = current();
    setting("timeout", &c.timeout.to_string())
        .parse::<u64>()
        .unwrap_or(c.timeout)
}

/// Return configured circuit breaker limits (max consecutive, window size, threshold in window).
pub fn circuit_breaker_limits() -> (u64, usize, usize) {
    let cb = &current().circuit_breaker;
    (
        cb.max_consecutive_denials,
        cb.recent_denials_window,
        cb.recent_denials_threshold,
    )
}

/// Outcome of permission rules evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PermissionOutcome {
    Allow(String),
    Deny(String),
}

/// Check permission rules for an incoming tool call payload.
///
/// Responsibility:
/// Evaluates `deny` and `allow` rules against tool name and arguments.
///
/// Precedence:
/// Deny rules always evaluate before allow rules (Deny > Allow).
///
/// How it works:
/// 1. Evaluates all rules in `deny`. If any rule matches, returns `PermissionOutcome::Deny`.
/// 2. Evaluates all rules in `allow`. If matched, returns `PermissionOutcome::Allow`.
/// 3. If no rule matches, returns `None`.
pub fn check_permissions(tool: &str, args: &Value) -> Option<PermissionOutcome> {
    let cfg = current();

    // 1. Check Deny rules
    if let Some(reason) = check_rules_match(tool, args, &cfg.deny.0, true) {
        return Some(PermissionOutcome::Deny(reason));
    }

    // 2. Check Allow rules
    if let Some(reason) = check_rules_match(tool, args, &cfg.allow.0, false) {
        return Some(PermissionOutcome::Allow(reason));
    }

    None
}

/// Evaluate a list of permission rules against a tool call.
fn check_rules_match(
    tool: &str,
    args: &Value,
    rules: &[PermissionRule],
    is_deny: bool,
) -> Option<String> {
    if rules.is_empty() {
        return None;
    }

    if tool == "run_command" {
        let command_line = args["CommandLine"].as_str().unwrap_or("").trim();
        if command_line.is_empty() {
            return None;
        }

        let mut subcommands = parser::commands(command_line);
        if subcommands.is_empty() {
            subcommands.push(command_line.to_string());
        }

        if is_deny {
            // For deny: If ANY subcommand matches ANY deny rule, reject immediately.
            for subcmd in &subcommands {
                for rule in rules {
                    if rule.matches_single_command(subcmd) {
                        return Some(format!(
                            "Blocked by permission rule '{}' for command '{}'",
                            rule.raw, subcmd
                        ));
                    }
                }
            }
        } else {
            // For allow: EVERY subcommand must match at least one allow rule.
            let mut matched_rules = Vec::new();
            let all_allowed = subcommands.iter().all(|subcmd| {
                for rule in rules {
                    if rule.matches_single_command(subcmd) {
                        matched_rules.push(rule.raw.as_str());
                        return true;
                    }
                }
                false
            });

            if all_allowed && !matched_rules.is_empty() {
                return Some(format!(
                    "Allowed by permission rule(s): {}",
                    matched_rules.join(", ")
                ));
            }
        }
        return None;
    }

    // File writing tools
    if matches!(
        tool,
        "write_file" | "write_to_file" | "replace_file_content" | "edit_file" | "apply_patch"
    ) {
        let target_str = args["TargetFile"]
            .as_str()
            .or_else(|| args["target_file"].as_str())
            .or_else(|| args["FilePath"].as_str())
            .or_else(|| args["file_path"].as_str())
            .or_else(|| args["Path"].as_str())
            .or_else(|| args["path"].as_str())
            .unwrap_or("")
            .trim();

        if !target_str.is_empty() {
            let target_path = Path::new(target_str);
            for rule in rules {
                if rule.matches_path(target_path, true) {
                    let verb = if is_deny { "Blocked" } else { "Allowed" };
                    return Some(format!(
                        "{verb} by permission rule '{}' for path '{}'",
                        rule.raw, target_str
                    ));
                }
            }
        }
    }

    // File reading tools
    if matches!(
        tool,
        "read_file" | "view_file" | "grep_search" | "list_dir" | "find_by_name"
    ) {
        let target_str = args["AbsolutePath"]
            .as_str()
            .or_else(|| args["SearchPath"].as_str())
            .or_else(|| args["DirectoryPath"].as_str())
            .or_else(|| args["SearchDirectory"].as_str())
            .or_else(|| args["path"].as_str())
            .or_else(|| args["file_path"].as_str())
            .or_else(|| args["FilePath"].as_str())
            .or_else(|| args["TargetFile"].as_str())
            .or_else(|| args["target_file"].as_str())
            .unwrap_or("")
            .trim();

        if !target_str.is_empty() {
            let target_path = Path::new(target_str);
            for rule in rules {
                if rule.matches_path(target_path, false) {
                    let verb = if is_deny { "Blocked" } else { "Allowed" };
                    return Some(format!(
                        "{verb} by permission rule '{}' for path '{}'",
                        rule.raw, target_str
                    ));
                }
            }
        }
    }

    // URL tools
    if matches!(tool, "read_url_content" | "read_browser_page") {
        let url_str = args["Url"]
            .as_str()
            .or_else(|| args["url"].as_str())
            .unwrap_or("")
            .trim();
        if !url_str.is_empty() {
            for rule in rules {
                if rule.matches_url(url_str) {
                    let verb = if is_deny { "Blocked" } else { "Allowed" };
                    return Some(format!(
                        "{verb} by permission rule '{}' for URL '{}'",
                        rule.raw, url_str
                    ));
                }
            }
        }
    }

    // Generic tool names
    for rule in rules {
        if rule.matches_tool_name(tool) {
            let verb = if is_deny { "Blocked" } else { "Allowed" };
            return Some(format!(
                "{verb} by permission rule '{}' for tool '{tool}'",
                rule.raw
            ));
        }
    }

    None
}
