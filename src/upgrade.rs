use crate::{config, daemon};
use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const RELEASES: &str = "https://github.com/jjyr/agy-auto-approve/releases";
const NAME: &str = "agy-auto-approve";

fn run(command: &mut Command) -> Result<()> {
    let status = command
        .stdin(Stdio::null())
        .status()
        .context("Could not launch upgrade command")?;
    if !status.success() {
        bail!("Upgrade command failed ({status})");
    }
    Ok(())
}
fn fetch(url: &str, output: &Path) -> Result<String> {
    let result = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--retry",
            "3",
            "--connect-timeout",
            "15",
            "--max-time",
            "180",
            "--write-out",
            "%{url_effective}",
            "--output",
        ])
        .arg(output)
        .arg(url)
        .stdin(Stdio::null())
        .output()
        .context("Release updates require curl")?;
    if !result.status.success() {
        bail!(
            "Download failed: {}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    Ok(String::from_utf8(result.stdout)?.trim().to_owned())
}
fn stable_version(version: &str) -> Result<String> {
    let version = version.strip_prefix('v').unwrap_or(version);
    if !regex::Regex::new(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")?.is_match(version)
    {
        bail!("Expected a stable version such as v1.2.3");
    }
    Ok(version.to_owned())
}
fn target() -> Result<String> {
    let os = match std::env::consts::OS {
        "macos" => "apple-darwin",
        "linux" => "unknown-linux-musl",
        other => bail!("Unsupported OS: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        other => bail!("Unsupported architecture: {other}"),
    };
    Ok(format!("{arch}-{os}"))
}
// Match the actual installation root, including `cargo install --root`, not just PATH.
fn registry_source(executable: &Path) -> Result<Option<(PathBuf, String)>> {
    let Some(bin) = executable.parent() else {
        return Ok(None);
    };
    if bin.file_name().is_none_or(|name| name != "bin") {
        return Ok(None);
    }
    let Some(root) = bin.parent() else {
        return Ok(None);
    };
    let metadata = root.join(".crates2.json");
    let bytes = match fs::read(&metadata) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let data: Value =
        serde_json::from_slice(&bytes).context("Invalid Cargo installation records")?;
    let installs = data["installs"]
        .as_object()
        .context("Invalid Cargo installs metadata")?;
    for (package, details) in installs {
        if !package.starts_with(&format!("{NAME} "))
            || !details["bins"]
                .as_array()
                .is_some_and(|bins| bins.iter().any(|b| b == NAME))
        {
            continue;
        }
        if let Some((_, source)) = package.split_once(" (registry+") {
            let index = source
                .strip_suffix(')')
                .context("Invalid Cargo registry source")?;
            return Ok(Some((root.to_owned(), index.to_owned())));
        }
        bail!(
            "This Cargo installation is not from a registry. Only registry and standalone binary updates are supported."
        );
    }
    Ok(None)
}
fn read_config(path: &Path) -> Result<Value> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("Invalid JSON in {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(json!({})),
        Err(e) => Err(e.into()),
    }
}
/// Detect whether agy-auto-approve is currently installed and enabled for CLI and Desktop.
///
/// Responsibility:
/// Identifies the active plugin scope before an executable upgrade so the
/// configuration refresh can target the correct environments.
///
/// How it works:
/// 1. Checks if the plugin exists in ~/.gemini/config/plugins/agy-auto-approve.
/// 2. If present, verifies that the plugin is not disabled in manifests or config.
/// 3. Reads the .scope metadata file if available to determine CLI and Desktop scopes.
/// 4. Checks legacy ~/.gemini/antigravity-cli/plugins/ directory if present.
/// 5. Falls back to legacy ~/.gemini/config/hooks.json and config.json sidecar detection.
fn installed_scope() -> Result<(bool, bool)> {
    let home = config::home();
    let desktop_plugin_dir = home.join(".gemini/config/plugins").join(NAME);
    let cli_plugin_dir = home.join(".gemini/antigravity-cli/plugins").join(NAME);

    let desktop_plugin_exists = desktop_plugin_dir.join("plugin.json").exists()
        || desktop_plugin_dir.join("hooks.json").exists();
    let cli_plugin_exists =
        cli_plugin_dir.join("plugin.json").exists() || cli_plugin_dir.join("hooks.json").exists();

    if desktop_plugin_exists || cli_plugin_exists {
        if desktop_plugin_exists {
            let plugin_json = read_config(&desktop_plugin_dir.join("plugin.json"))?;
            let plugin_hooks = read_config(&desktop_plugin_dir.join("hooks.json"))?;
            let desktop = read_config(&home.join(".gemini/config/config.json"))?;
            let disabled_manifest = plugin_json["disabled"] == true;
            let disabled_hooks = plugin_hooks[NAME]["enabled"] == false;
            let disabled_config = desktop["plugins"][NAME]["enabled"] == false;
            let is_enabled = !disabled_manifest && !disabled_hooks && !disabled_config;

            if !is_enabled {
                return Ok((false, false));
            }

            // Check if .scope metadata file exists from installation.
            let scope_file = desktop_plugin_dir.join(".scope");
            if let Ok(scope_data) = read_config(&scope_file) {
                let cli = scope_data["cli"].as_bool().unwrap_or(true);
                let desktop = scope_data["desktop"].as_bool().unwrap_or(true);
                return Ok((cli, desktop));
            }

            // Without .scope file, check legacy CLI plugin directory.
            let cli_enabled = if cli_plugin_exists {
                let cli_json = read_config(&cli_plugin_dir.join("plugin.json"))?;
                let cli_hooks = read_config(&cli_plugin_dir.join("hooks.json"))?;
                cli_json["disabled"] != true && cli_hooks[NAME]["enabled"] != false
            } else {
                true
            };

            return Ok((cli_enabled, true));
        }

        if cli_plugin_exists {
            let cli_json = read_config(&cli_plugin_dir.join("plugin.json"))?;
            let cli_hooks = read_config(&cli_plugin_dir.join("hooks.json"))?;
            let cli_enabled = cli_json["disabled"] != true && cli_hooks[NAME]["enabled"] != false;
            return Ok((cli_enabled, false));
        }
    }

    // Fall back to legacy hooks.json and config.json sidecar detection.
    let base = home.join(".gemini/config");
    let hooks = read_config(&base.join("hooks.json"))?;
    let desktop = read_config(&base.join("config.json"))?;
    let hook = &hooks[NAME];
    let sidecar = &desktop["sidecars"]["agy-auto-approve/approver"];
    Ok((
        hook.is_object() && hook["enabled"] != false,
        sidecar.is_object() && sidecar["enabled"] != false,
    ))
}
fn release_update(executable: &Path, version: Option<&str>) -> Result<()> {
    let target = target()?;
    let scratch = tempfile::tempdir()?;
    let version = match version {
        Some(version) => stable_version(version)?,
        None => {
            let url = fetch(
                &format!("{RELEASES}/latest"),
                &scratch.path().join("latest"),
            )?;
            stable_version(
                url.strip_prefix(&format!("{RELEASES}/tag/"))
                    .context("Cannot resolve latest stable release")?,
            )?
        }
    };
    let asset = format!("{NAME}-v{version}-{target}.tar.gz");
    let archive_path = scratch.path().join(&asset);
    println!("Downloading {asset}");
    fetch(
        &format!("{RELEASES}/download/v{version}/{asset}"),
        &archive_path,
    )?;
    let sums = scratch.path().join("SHA256SUMS");
    fetch(&format!("{RELEASES}/download/v{version}/SHA256SUMS"), &sums)?;
    let sums = fs::read_to_string(sums)?;
    let hashes: Vec<_> = sums
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.len() == 2 && fields[1] == asset).then(|| fields[0])
        })
        .collect();
    if hashes.len() != 1
        || hashes[0].len() != 64
        || !hashes[0].bytes().all(|c| c.is_ascii_hexdigit())
    {
        bail!("Missing, duplicate, or invalid checksum for {asset}");
    }
    let mut digest = Sha256::new();
    let mut input = fs::File::open(&archive_path)?;
    let mut buffer = [0; 65536];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    if format!("{:x}", digest.finalize()) != hashes[0].to_ascii_lowercase() {
        bail!("SHA-256 mismatch; installed binary unchanged");
    }
    let mut staged = tempfile::NamedTempFile::new_in(
        executable
            .parent()
            .context("Missing executable directory")?,
    )?;
    let mut archive = tar::Archive::new(GzDecoder::new(fs::File::open(archive_path)?));
    let mut count = 0;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.as_ref() != Path::new(NAME)
            || !entry.header().entry_type().is_file()
            || count != 0
        {
            bail!("Unexpected release archive entry");
        }
        std::io::copy(&mut entry, staged.as_file_mut())?;
        count += 1;
    }
    if count != 1 {
        bail!("Release archive does not contain the binary");
    }
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    staged.as_file().sync_all()?;
    // Close the writable handle before execution (required on Linux).
    let staged = staged.into_temp_path();
    let result = Command::new(&staged)
        .arg("--version")
        .stdin(Stdio::null())
        .output()?;
    if !result.status.success()
        || String::from_utf8_lossy(&result.stdout).trim() != format!("{NAME} {version}")
    {
        bail!("Downloaded binary failed version/platform validation");
    }
    staged.persist(executable).map_err(|e| e.error)?;
    println!("Installed {NAME} {version}");
    Ok(())
}
pub async fn update(version: Option<&str>) -> Result<()> {
    let version = version.map(stable_version).transpose()?;
    let executable = std::env::current_exe()?.canonicalize()?;
    let (cli, desktop) = installed_scope()?;
    if let Some((root, index)) = registry_source(&executable)? {
        println!("Updating Cargo registry installation");
        let mut cargo = Command::new("cargo");
        cargo
            .args(["install", NAME, "--locked", "--force", "--root"])
            .arg(root)
            .arg("--index")
            .arg(index);
        if let Some(version) = &version {
            cargo.arg("--version").arg(format!("={version}"));
        }
        run(&mut cargo)?;
    } else {
        release_update(&executable, version.as_deref())?;
    }
    if cli || desktop {
        let mut install = Command::new(&executable);
        install.arg("install");
        if !desktop {
            install.arg("--cli-only");
        }
        if !cli {
            install.arg("--desktop-only");
        }
        run(&mut install).context(
            "Binary upgraded, but plugin configuration refresh failed; run install to retry",
        )?;
    } else {
        println!("No enabled plugin found. Run `agy-auto-approve install` to enable it.");
    }
    if let Ok(status) =
        daemon::request(&config::socket_path(), &json!({"action":"status"}), 1).await
        && status["status"] == "running"
    {
        run(Command::new(&executable).args(["daemon", "stop"]))
            .context("Upgrade completed, but the old daemon could not be stopped")?;
        println!("CLI will start the new daemon on its next review request.");
    }
    if desktop {
        println!("Restart Antigravity Desktop to load the updated hook configuration.");
    }
    Ok(())
}
