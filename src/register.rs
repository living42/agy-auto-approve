use crate::config;
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{fs, path::Path};

/// Read, update, and atomically save a JSON file.
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
    fs::create_dir_all(path.parent().unwrap())?;
    let tmp = path.with_extension(format!("{}.tmp", std::process::id()));
    fs::write(&tmp, serde_json::to_vec_pretty(&data)?)?;
    fs::rename(tmp, path)?;
    println!("Updated {}", path.display());
    Ok(())
}

/// Ensure a field in a JSON object exists as an object and return a mutable reference.
fn object_field<'a>(v: &'a mut Value, key: &str) -> Result<&'a mut Value> {
    if v.get(key).is_none() {
        v[key] = json!({});
    }
    if !v[key].is_object() {
        bail!("Expected {key} to be an object");
    }
    Ok(&mut v[key])
}

/// Register agy-auto-approve hooks and clean up legacy sidecars.
pub fn register(cli_only: bool, desktop_only: bool) -> Result<()> {
    let exe = std::env::current_exe()?.canonicalize()?;
    let executable = exe.to_str().context("Executable path is not UTF-8")?;
    let quoted = format!("'{}'", executable.replace('\'', "'\"'\"'"));
    let base = config::home().join(".gemini/config");

    // Register PreToolUse and PostToolUse lifecycle hooks.
    update(&base.join("hooks.json"), |v| {
        v["agy-auto-approve"] = json!({
            "enabled": true,
            "PreToolUse": [{
                "matcher": "*",
                "hooks": [{"type": "command", "command": format!("{quoted} hook"), "timeout": 180}]
            }],
            "PostToolUse": [{
                "matcher": "*",
                "hooks": [{"type": "command", "command": format!("{quoted} post-hook"), "timeout": 60}]
            }]
        });
        Ok(())
    })?;

    // Configure CLI permissions in settings.json if present.
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

    // Clean up legacy sidecars from config.json and delete sidecar manifests.
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
