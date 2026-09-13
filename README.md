# agy-auto-approve

Automatic approval hooks and a persistent approval daemon for Antigravity CLI and Desktop, built as a single Rust executable. AI reviews use background `agy` CLI processes running in sandboxed, pure-reasoning mode.

Reviewer processes execute with their working directory in `~/.gemini/agy-auto-approve/state` and deny all tool calls. Per-conversation states are unified under `~/.gemini/agy-auto-approve/state/<source_cid>.json`.

## How it works

CLI and Desktop share the same approval pipeline. Local rules handle allowlisted
read-only tools and blocked commands; other requests go to an AI reviewer that
assesses risk and user authorization.

```text
Antigravity CLI / Desktop
           |
     Approval hook
           |
     Read-only tool? -------- yes ------> Allow
           | no
     Blocklisted command? -- yes ------> Deny
           | no
     Circuit breaker open? - yes ------> Ask user
           | no
     Persistent daemon
           |
     agy Reviewer Process -------------> Allow / Deny
           |
     Error or timeout -----------------> Deny
```

The daemon manages reviewer sessions per source conversation, allowing the model service
to reuse KV/prompt caches for shared context. Reviewer processes idle for 10 minutes are
automatically reclaimed while state is preserved on disk.
Repeated AI-review denials trip the circuit breaker, requiring user review on
subsequent requests. User approvals during PostToolUse automatically reset the breaker.
Decisions and reasons are logged locally.

## Install

Choose one way to install the binary.

Download a [GitHub Release](https://github.com/jjyr/agy-auto-approve/releases/latest)
(macOS or Linux, ARM64 or x86_64). Set the release tag and your platform target:

```bash
VERSION=v0.4.2
TARGET=aarch64-apple-darwin
curl -fLO "https://github.com/jjyr/agy-auto-approve/releases/download/$VERSION/agy-auto-approve-$VERSION-$TARGET.tar.gz"
tar -xzf "agy-auto-approve-$VERSION-$TARGET.tar.gz"
mkdir -p ~/.local/bin
mv agy-auto-approve ~/.local/bin/
```

Targets: `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`aarch64-unknown-linux-musl`, `x86_64-unknown-linux-musl`.
Make sure `~/.local/bin` is on your `PATH`.

Or install from crates.io once the crate is published (requires Rust/Cargo and a C compiler):

```bash
cargo install agy-auto-approve --locked
```

Then install the lifecycle hooks:

```bash
agy-auto-approve install
```

See the [command reference](docs/commands.md) for upgrades and installation options.

## Logs

```bash
agy-auto-approve logs                     # Show recent approvals
agy-auto-approve logs -f                  # Follow new approvals
agy-auto-approve logs --decision deny     # Show denied approvals
agy-auto-approve logs show APPROVAL_ID    # Show the full approval record
```

Logs are stored in `~/.gemini/agy-auto-approve` and can be read without a running daemon.

For all commands and options, see the [command reference](docs/commands.md). For more details, see the [daemon architecture](docs/daemon.md) and [policy background](docs/auto_approver_architecture.md).

## License

MIT
