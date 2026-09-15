use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

const VERSION: &str = "v0.3.0";
const BINARY: &str = r#"#!/bin/sh
case "$1" in
  --version) echo 'agy-auto-approve 0.3.0';;
  install) printf '%s\n' "$*" >> "$HOME/registered";;
  *) exit 1;;
esac
"#;
fn executable(path: &Path, text: &str) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}
struct Fixture {
    dir: tempfile::TempDir,
    asset: String,
}
impl Fixture {
    fn new(system: &str, machine: &str, target: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for name in ["bin", "assets", "payload", "home", "scratch"] {
            fs::create_dir(dir.path().join(name)).unwrap();
        }
        executable(&dir.path().join("payload/agy-auto-approve"), BINARY);
        let asset = format!("agy-auto-approve-{VERSION}-{target}.tar.gz");
        assert!(
            Command::new("tar")
                .env("COPYFILE_DISABLE", "1")
                .arg("-czf")
                .arg(dir.path().join("assets").join(&asset))
                .arg("-C")
                .arg(dir.path().join("payload"))
                .arg("agy-auto-approve")
                .status()
                .unwrap()
                .success()
        );
        let hash = Command::new("/bin/sh").args(["-c", "if command -v sha256sum >/dev/null 2>&1; then sha256sum \"$1\"; else shasum -a 256 \"$1\"; fi", "hash"])
            .arg(dir.path().join("assets").join(&asset)).output().unwrap();
        assert!(hash.status.success());
        let hash = String::from_utf8(hash.stdout)
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned();
        fs::write(
            dir.path().join("assets/SHA256SUMS"),
            format!("{hash}  {asset}\n"),
        )
        .unwrap();
        executable(
            &dir.path().join("bin/uname"),
            &format!(
                "#!/bin/sh\ncase \"$1\" in -s) echo '{system}';; -m) echo '{machine}';; *) exit 1;; esac\n"
            ),
        );
        executable(
            &dir.path().join("bin/curl"),
            r#"#!/bin/sh
printf '%s\n' "$@" >> "$REQUEST_LOG"
output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) output=$2; shift 2;;
    --write-out|--proto|--proto-redir|--retry|--connect-timeout|--max-time) shift 2;;
    --*) shift;;
    *) url=$1; shift;;
  esac
done
case "$url" in
  https://github.com/jjyr/agy-auto-approve/releases/latest)
    printf 'https://github.com/jjyr/agy-auto-approve/releases/tag/%s' "${LATEST_TAG:-v0.3.0}";;
  https://github.com/jjyr/agy-auto-approve/releases/download/*)
    [ "${FAIL_DOWNLOAD:-0}" != 1 ] || exit 22
    cp "$ASSET_DIR/${url##*/}" "$output";;
  *) exit 22;;
esac
"#,
        );
        executable(
            &dir.path().join("bin/agy"),
            r#"#!/bin/sh
case "$1" in
  plugin)
    case "$2" in
      install)
        target="$3"
        dest="$HOME/.gemini/config/plugins/agy-auto-approve"
        mkdir -p "$dest"
        cp -R "$target/." "$dest/"
        manifest="$HOME/.gemini/config/import_manifest.json"
        mkdir -p "$(dirname "$manifest")"
        if [ ! -f "$manifest" ]; then
          printf '{"imports":[{"name":"agy-auto-approve","source":"antigravity","importedAt":"2026-09-15T00:00:00Z","components":["hooks"]}]}\n' > "$manifest"
        fi
        exit 0
        ;;
      list)
        cat "$HOME/.gemini/config/import_manifest.json" 2>/dev/null || echo '{"imports":[]}'
        exit 0
        ;;
      validate)
        exit 0
        ;;
      *)
        exit 0
        ;;
    esac
    ;;
  --version)
    echo 'agy 2.0.0'
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"#,
        );
        fs::create_dir_all(dir.path().join("home/.local/bin")).unwrap();
        let _ = fs::copy(
            dir.path().join("bin/agy"),
            dir.path().join("home/.local/bin/agy"),
        );
        fs::copy(
            env!("CARGO_BIN_EXE_agy-auto-approve"),
            dir.path().join("home/.local/bin/agy-auto-approve"),
        )
        .unwrap();
        Self { dir, asset }
    }
    fn command(&self) -> Command {
        let mut c = Command::new(self.installed());
        c.arg("update")
            .env("HOME", self.dir.path().join("home"))
            .env("AGY_BIN", self.dir.path().join("bin/agy"))
            .env("AGY_APPROVER_SOCKET", self.dir.path().join("approver.sock"))
            .env("AGY_APPROVER_STATE_DIR", self.dir.path().join("state"))
            .env("AGY_AUTO_APPROVE_LOG_DIR", self.dir.path().join("logs"))
            .env("TMPDIR", self.dir.path().join("scratch"))
            .env(
                "PATH",
                format!(
                    "{}:{}",
                    self.dir.path().join("bin").display(),
                    std::env::var("PATH").unwrap_or_default()
                ),
            )
            .env("ASSET_DIR", self.dir.path().join("assets"))
            .env("REQUEST_LOG", self.dir.path().join("requests"))
            .current_dir(self.dir.path());
        c
    }
    fn run(&self, mut command: Command, flags: &[&str]) -> std::process::Output {
        command.args(flags).output().unwrap()
    }
    fn installed(&self) -> std::path::PathBuf {
        self.dir.path().join("home/.local/bin/agy-auto-approve")
    }
    fn assert_clean(&self) {
        assert_eq!(
            fs::read_dir(self.dir.path().join("scratch"))
                .unwrap()
                .count(),
            0
        );
    }
}

fn fixture() -> Fixture {
    let target = format!(
        "{}-{}",
        std::env::consts::ARCH,
        if cfg!(target_os = "macos") {
            "apple-darwin"
        } else {
            "unknown-linux-musl"
        }
    );
    Fixture::new("unused", "unused", &target)
}
#[test]
fn release_update_resolves_latest_and_preserves_cli_scope() {
    let f = fixture();
    assert!(
        Command::new(f.installed())
            .arg("install")
            .arg("--cli-only")
            .env("HOME", f.dir.path().join("home"))
            .status()
            .unwrap()
            .success()
    );
    let out = f.run(f.command(), &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(fs::read_to_string(f.installed()).unwrap(), BINARY);
    assert_eq!(
        fs::read_to_string(f.dir.path().join("home/registered")).unwrap(),
        "install --cli-only\n"
    );
    let requests = fs::read_to_string(f.dir.path().join("requests")).unwrap();
    assert_eq!(requests.matches("/releases/latest").count(), 1);
    assert!(requests.contains(&format!("/download/{VERSION}/{}", f.asset)));
    f.assert_clean();
}
#[test]
fn explicit_version_does_not_enable_uninstalled_plugins() {
    let f = fixture();
    let out = f.run(f.command(), &["--version", VERSION]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        !fs::read_to_string(f.dir.path().join("requests"))
            .unwrap()
            .contains("/latest")
    );
    assert!(!f.dir.path().join("home/registered").exists());
    f.assert_clean();
}
#[test]
fn failed_release_preserves_binary() {
    for failure in [
        "download",
        "mismatch",
        "missing",
        "duplicate",
        "version",
        "archive",
    ] {
        let f = fixture();
        let previous = fs::read(f.installed()).unwrap();
        let mut c = f.command();
        let sums = f.dir.path().join("assets/SHA256SUMS");
        match failure {
            "download" => {
                c.env("FAIL_DOWNLOAD", "1");
            }
            "mismatch" => fs::write(&sums, format!("{}  {}\n", "0".repeat(64), f.asset)).unwrap(),
            "missing" => fs::write(&sums, "").unwrap(),
            "duplicate" => fs::write(&sums, fs::read_to_string(&sums).unwrap().repeat(2)).unwrap(),
            "version" => {
                let new_asset = f.asset.replace(VERSION, "v9.0.0");
                fs::rename(
                    f.dir.path().join("assets").join(&f.asset),
                    f.dir.path().join("assets").join(&new_asset),
                )
                .unwrap();
                fs::write(
                    &sums,
                    fs::read_to_string(&sums)
                        .unwrap()
                        .replace(VERSION, "v9.0.0"),
                )
                .unwrap();
                c.env("LATEST_TAG", "v9.0.0");
            }
            "archive" => {
                fs::write(
                    f.dir.path().join("assets").join(&f.asset),
                    b"not an archive",
                )
                .unwrap();
                use sha2::{Digest, Sha256};
                fs::write(
                    &sums,
                    format!("{:x}  {}\n", Sha256::digest(b"not an archive"), f.asset),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        let out = f.run(c, &[]);
        assert!(!out.status.success(), "{failure}");
        assert_eq!(fs::read(f.installed()).unwrap(), previous);
        assert!(!f.dir.path().join("home/registered").exists());
        f.assert_clean();
    }
}
#[test]
fn registry_installation_uses_cargo_and_original_root() {
    let f = fixture();
    let root = f.installed().parent().unwrap().parent().unwrap().to_owned();
    fs::write(root.join(".crates2.json"), r#"{"installs":{"agy-auto-approve 0.4.2 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["agy-auto-approve"]}}}"#).unwrap();
    executable(
        &f.dir.path().join("bin/cargo"),
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$HOME/cargo-args\"\n",
    );
    let out = f.run(f.command(), &["--version", "v0.5.0"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let args = fs::read_to_string(f.dir.path().join("home/cargo-args")).unwrap();
    assert!(args.contains("install\nagy-auto-approve\n"));
    assert!(args.contains(&format!(
        "--root\n{}\n",
        root.canonicalize().unwrap().display()
    )));
    assert!(args.contains("--version\n=0.5.0\n"));
    assert!(!f.dir.path().join("requests").exists());
}
#[test]
fn invalid_version_fails_before_download() {
    let f = fixture();
    assert!(
        !f.run(f.command(), &["--version", "../bad"])
            .status
            .success()
    );
    assert!(!f.dir.path().join("requests").exists());
}

#[test]
fn disabled_cli_is_preserved_when_updating_desktop() {
    let f = fixture();
    let base = f.dir.path().join("home/.gemini/config");
    fs::create_dir_all(&base).unwrap();
    let hooks = r#"{"agy-auto-approve":{"enabled":false},"other":{"enabled":true}}"#;
    fs::write(base.join("hooks.json"), hooks).unwrap();
    fs::write(
        base.join("config.json"),
        r#"{"sidecars":{"agy-auto-approve/approver":{"enabled":true}}}"#,
    )
    .unwrap();
    let out = f.run(f.command(), &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read_to_string(f.dir.path().join("home/registered")).unwrap(),
        "install --desktop-only\n"
    );
    assert_eq!(fs::read_to_string(base.join("hooks.json")).unwrap(), hooks);
}

#[test]
fn cargo_failure_does_not_fall_back_to_release_or_refresh_configuration() {
    let f = fixture();
    let root = f.installed().parent().unwrap().parent().unwrap().to_owned();
    fs::write(root.join(".crates2.json"), r#"{"installs":{"agy-auto-approve 0.4.2 (registry+https://example.com/index)":{"bins":["agy-auto-approve"]}}}"#).unwrap();
    executable(&f.dir.path().join("bin/cargo"), "#!/bin/sh\nexit 1\n");
    let previous = fs::read(f.installed()).unwrap();
    assert!(!f.run(f.command(), &[]).status.success());
    assert_eq!(fs::read(f.installed()).unwrap(), previous);
    assert!(!f.dir.path().join("requests").exists());
    assert!(!f.dir.path().join("home/registered").exists());
}

#[test]
fn unrelated_cargo_metadata_does_not_select_registry_update() {
    let f = fixture();
    let root = f.installed().parent().unwrap().parent().unwrap().to_owned();
    fs::write(
        root.join(".crates2.json"),
        r#"{"installs":{"other 1.0.0 (registry+https://example.com/index)":{"bins":["other"]}}}"#,
    )
    .unwrap();
    let out = f.run(f.command(), &[]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(f.dir.path().join("requests").exists());
}

#[test]
fn successful_update_stops_existing_daemon() {
    let f = fixture();
    let root = f.installed().parent().unwrap().parent().unwrap().to_owned();
    fs::write(root.join(".crates2.json"), r#"{"installs":{"agy-auto-approve 0.4.2 (registry+https://github.com/rust-lang/crates.io-index)":{"bins":["agy-auto-approve"]}}}"#).unwrap();
    executable(&f.dir.path().join("bin/cargo"), "#!/bin/sh\nexit 0\n");
    let mut daemon = Command::new(f.installed())
        .args(["daemon", "run", "--idle-timeout", "5"])
        .env("HOME", f.dir.path().join("home"))
        .env("AGY_APPROVER_SOCKET", f.dir.path().join("approver.sock"))
        .env("AGY_APPROVER_STATE_DIR", f.dir.path().join("state"))
        .env("AGY_AUTO_APPROVE_LOG_DIR", f.dir.path().join("logs"))
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..250 {
        if f.dir.path().join("approver.sock").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        f.dir.path().join("approver.sock").exists(),
        "approver.sock must exist before update runs"
    );
    let out = f.run(f.command(), &[]);
    let stopped = !f.dir.path().join("approver.sock").exists();
    let _ = daemon.kill();
    let _ = daemon.wait();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("CLI will start the new daemon"));
    assert!(stopped);
}
