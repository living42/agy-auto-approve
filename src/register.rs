use crate::config;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// Read, update, and atomically save a JSON file.
///
/// Responsibility:
/// Modifies existing JSON files safely without data loss on failure.
///
/// How it works:
/// Reads and parses the target JSON file.
/// Applies the transformation callback.
/// Writes output to a temporary file in the same directory.
/// Renames the temporary file over the target atomically.
fn update(path: &Path, f: impl FnOnce(&mut Value) -> Result<()>) -> Result<()> {
    let mut data = match fs::read(path) {
        Ok(bytes) => serde_json::from_slice::<Value>(&bytes)
            .with_context(|| format!("Invalid JSON in {}; leaving it unchanged", path.display()))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => json!({}),
        Err(e) => return Err(e.into()),
    };
    if !data.is_object() {
        bail!("Expected JSON object in {}", path.display());
    }
    f(&mut data)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&tmp, serde_json::to_vec_pretty(&data)?)?;
    fs::rename(tmp, path)?;
    println!("Updated {}", path.display());
    Ok(())
}

/// Ensure a field in a JSON object exists as an object and return a mutable reference.
///
/// Responsibility:
/// Navigates or initializes nested JSON object hierarchies.
fn object_field<'a>(v: &'a mut Value, key: &str) -> Result<&'a mut Value> {
    if v.get(key).is_none() {
        v[key] = json!({});
    }
    if !v[key].is_object() {
        bail!("Expected {key} to be an object");
    }
    Ok(&mut v[key])
}

const NAME: &str = "agy-auto-approve";
const PLUGIN_DESCRIPTION: &str = "Antigravity plugin for intelligent auto-approval with safety blacklists and read-only LLM guard evaluation.";

/// Find the 'agy' binary on the system.
///
/// Responsibility:
/// Resolves the Antigravity CLI executable path.
///
/// How it works:
/// Checks `config::agy_bin()`.
/// If found on disk, returns the path.
/// Otherwise runs `agy --version` to test if accessible via PATH or alias.
/// Fails with an informative error if 'agy' is not available.
fn resolve_agy() -> Result<PathBuf> {
    let agy = config::agy_bin();
    if agy.is_file() {
        return Ok(agy);
    }
    if let Ok(status) = Command::new(&agy)
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        && status.success()
    {
        return Ok(agy);
    }
    bail!(
        "Could not find 'agy' executable in PATH, ~/.local/bin/agy, or ~/.gemini/antigravity-cli/bin/agy. Antigravity CLI is required to install the plugin."
    );
}

/// Register agy-auto-approve as a plugin by calling 'agy plugin install'.
///
/// Responsibility:
/// Stages the plugin manifest and hooks, invokes 'agy plugin install',
/// and cleans up legacy registration configurations.
///
/// How it works:
/// 1. Verifies that 'agy' CLI executable is installed and available.
/// 2. Canonicalizes the current binary path and quotes it for shell execution.
/// 3. Creates a temporary staging directory with 'plugin.json' and 'hooks.json'.
/// 4. Executes 'agy plugin install <staging_dir>' to copy and register the plugin.
/// 5. Cleans up legacy hook entries from ~/.gemini/config/hooks.json.
/// 6. Cleans up legacy sidecars and stale plugin copies.
/// 7. Configures CLI development permissions in settings.json when applicable.
pub fn register(cli_only: bool, desktop_only: bool) -> Result<()> {
    let agy = resolve_agy()?;
    println!("Using Antigravity CLI at {}", agy.display());

    let exe = std::env::current_exe()?.canonicalize()?;
    let executable = exe.to_str().context("Executable path is not UTF-8")?;
    let quoted = format!("'{}'", executable.replace('\'', "'\"'\"'"));
    let home = config::home();
    let base = home.join(".gemini/config");

    // 1. Create temporary staging directory for the plugin.
    let staged = tempfile::tempdir().context("Failed to create temporary staging directory")?;
    let staged_dir = staged.path();

    let plugin_manifest = json!({
        "$schema": "https://antigravity.google/schemas/v1/plugin.json",
        "name": NAME,
        "description": PLUGIN_DESCRIPTION,
    });
    fs::write(
        staged_dir.join("plugin.json"),
        serde_json::to_vec_pretty(&plugin_manifest)?,
    )?;

    let hooks_manifest = json!({
        NAME: {
            "enabled": true,
            "PreToolUse": [{
                "matcher": "*",
                "hooks": [{
                    "type": "command",
                    "command": format!("{quoted} hook"),
                    "timeout": 180
                }]
            }],
            "PostToolUse": [{
                "matcher": "*",
                "hooks": [{
                    "type": "command",
                    "command": format!("{quoted} post-hook"),
                    "timeout": 60
                }]
            }]
        }
    });
    fs::write(
        staged_dir.join("hooks.json"),
        serde_json::to_vec_pretty(&hooks_manifest)?,
    )?;

    // Record installation scope for update detection.
    let scope_data = json!({
        "cli": !desktop_only,
        "desktop": !cli_only,
    });
    fs::write(
        staged_dir.join(".scope"),
        serde_json::to_vec_pretty(&scope_data)?,
    )?;

    // 2. Invoke 'agy plugin install <staged_dir>'.
    println!("Installing plugin via agy plugin install...");
    let status = Command::new(&agy)
        .args(["plugin", "install"])
        .arg(staged_dir)
        .stdin(Stdio::null())
        .status()
        .context("Failed to execute 'agy plugin install'")?;
    if !status.success() {
        bail!("'agy plugin install' failed with exit status: {status}");
    }
    println!("Plugin successfully installed via agy plugin install.");

    // 3. Remove legacy CLI plugin directory if present (~/.gemini/antigravity-cli/plugins/agy-auto-approve)
    let legacy_cli_plugin = home.join(".gemini/antigravity-cli/plugins").join(NAME);
    if legacy_cli_plugin.exists() {
        let _ = fs::remove_dir_all(&legacy_cli_plugin);
        println!(
            "Removed obsolete plugin directory {}",
            legacy_cli_plugin.display()
        );
    }

    // 4. Clean up legacy hook entry from ~/.gemini/config/hooks.json if present.
    let legacy_hooks = base.join("hooks.json");
    if legacy_hooks.exists() {
        update(&legacy_hooks, |v| {
            if let Some(obj) = v.as_object_mut()
                && obj.remove(NAME).is_some()
            {
                println!("Removed legacy hook entry from {}", legacy_hooks.display());
            }
            Ok(())
        })?;
    }

    // 5. Configure CLI permissions in settings.json if present.
    let settings = config::home().join(".gemini/antigravity-cli/settings.json");
    if !desktop_only && settings.exists() {
        update(&settings, |v| {
            let permissions = object_field(v, "permissions")?;
            if permissions.get("allow").is_none() {
                permissions["allow"] = json!([]);
            }
            let allow = permissions["allow"]
                .as_array_mut()
                .context("permissions.allow must be an array")?;
            for p in "gh npm npx yarn pnpm bun git python python3 pytest cargo go node make docker docker-compose curl cat echo ls mkdir cp touch grep find sh bash zsh head tail mise uv".split_whitespace() {
                let grant = json!(format!("command({p})"));
                if !allow.contains(&grant) {
                    allow.push(grant);
                }
            }
            allow.sort_by_key(Value::to_string);
            Ok(())
        })?;
    }

    // 6. Clean up legacy sidecars from config.json and delete sidecar manifests.
    if !cli_only {
        let config_file = base.join("config.json");
        if config_file.exists() {
            let _ = update(&config_file, |v| {
                if let Some(sidecars) = v.get_mut("sidecars").and_then(Value::as_object_mut) {
                    sidecars.remove("agy-auto-approve/approver");
                    sidecars.remove("approver");
                }
                Ok(())
            });
        }
        for relative in [
            "sidecars/approver/sidecar.json",
            "sidecars/agy-auto-approve/approver/sidecar.json",
        ] {
            let path = base.join(relative);
            if path.exists() {
                let _ = fs::remove_file(&path);
                println!("Removed legacy sidecar manifest {}", path.display());
            }
        }
    }

    Ok(())
}
