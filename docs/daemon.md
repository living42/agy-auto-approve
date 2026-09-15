# Daemon and Lifecycle Hooks Architecture

`agy-auto-approve` uses a unified background daemon and Antigravity lifecycle hooks (`hooks.json`) to provide auto-approval for both Antigravity Desktop and Antigravity CLI.

```
+-----------------------------------------------------------------------------------+
|                            Antigravity (CLI / Desktop)                            |
|                                                                                   |
|   +-----------------------+                         +-------------------------+   |
|   |  PreToolUse Hook      |                         |   PostToolUse Hook      |   |
|   |  (timeout: 180s)      |                         |   (timeout: 60s)        |   |
|   +-----------+-----------+                         +------------+------------+   |
+---------------|--------------------------------------------------|----------------+
                |                                                  |
                | IPC: "evaluate"                                  | IPC: reset breaker
                v                                                  v
+-----------------------------------------------------------------------------------+
|                        Approver Daemon (approver.sock)                            |
|                                                                                   |
|   +--------------------+     10m idle ticker      +---------------------------+   |
|   |   ReviewerPool     | -----------------------> | reclaim_idle / flush_all  |   |
|   +---------+----------+                          +---------------------------+   |
+-------------|---------------------------------------------------------------------+
              |
              | stdin / stdout (stream-json, sandbox, json-schema)
              | CWD: ~/.gemini/agy-auto-approve/state
              v
+-----------------------------------------------------------------------------------+
|                       agy Reviewer Worker Process                                 |
|                                                                                   |
|   * Evaluates proposed tool execution against prompt                              |
|   * Strict pure-reasoning evaluator (all tool execution forbidden)                |
|   * Emits structured evaluation matching GUARDIAN_OUTPUT_SCHEMA                   |
|   * Configurable evaluation timeout (default: 120s)                               |
+-----------------------------------------------------------------------------------+
```

---

## 1. Unified Lifecycle Hooks

Both Desktop and CLI use Antigravity lifecycle hooks loaded from their respective global plugin directories:
- CLI: `~/.gemini/antigravity-cli/plugins/agy-auto-approve/hooks.json`
- Desktop: `~/.gemini/config/plugins/agy-auto-approve/hooks.json`

The legacy sidecar approach (`sidecars` in `config.json`) was replaced to ensure identical behavior across Desktop and CLI without depending on internal host sidecar lifecycles.

```json
{
  "agy-auto-approve": {
    "enabled": true,
    "PreToolUse": [{
      "matcher": "*",
      "hooks": [{"type": "command", "command": "'~/.local/bin/agy-auto-approve' hook", "timeout": 180}]
    }],
    "PostToolUse": [{
      "matcher": "*",
      "hooks": [{"type": "command", "command": "'~/.local/bin/agy-auto-approve' post-hook", "timeout": 60}]
    }]
  }
}
```

- **PreToolUse (`hook`)**: Intercepts tool calls. Evaluates allowlist fast path (read-only tools, workspace file modifications), blocklist (dangerous commands), circuit breaker state, or dispatches to the background daemon.
- **PostToolUse (`post-hook`)**: Detects completed tool executions. If the tool call was approved by user confirmation after a tripped circuit breaker, the breaker is automatically reset.

---

## 2. Daemon and Reviewer Process Pool

### Working Directory Isolation
Every reviewer child process runs with working directory set to:
`~/.gemini/agy-auto-approve/state`
This isolates reviewer operations from the workspace of the source project.

### Pure Reasoning Mode (Tool Execution Denied)
Reviewer processes are invoked with:
```bash
agy --input-format stream-json \
    --output-format stream-json \
    --disable-slash-commands \
    --sandbox \
    --model <model> \
    --effort low \
    --json-schema '<GUARDIAN_OUTPUT_SCHEMA>'
```
Any tool call attempted by the reviewer process is immediately denied (fail-closed).

### 10-Minute Idle Reclamation
Reviewer processes with no activity for 10 minutes (600 seconds) are automatically terminated by the daemon ticker to reclaim CPU and memory.
The session metadata is preserved in `~/.gemini/agy-auto-approve/state/<source_cid>.json`.
When a new tool call arrives for a reclaimed session, the daemon automatically resumes the session using `--conversation <reviewer_cid>`.

### Non-Blocking Pool Concurrency
The reviewer pool separates session lookup/spawning from evaluation execution.
The pool lock is held only briefly to look up or spawn the worker handle (`Arc<tokio::sync::Mutex<ReviewerWorker>>`).
Evaluations run concurrently per source conversation, allowing `daemon status` and other operations to respond immediately.

---

## 3. Directory Layout and State

All runtime files reside under `~/.gemini/agy-auto-approve/`:

```text
~/.gemini/agy-auto-approve/
  ├── auto-approve.log           # Text log summaries
  ├── approvals.jsonl            # Correlated audit traces
  ├── approver.sock              # Unix domain socket (IPC)
  ├── approver.sock.lock         # Daemon lifetime exclusive lock
  └── state/                     # Unified state & reviewer working directory
      ├── <source_cid_1>.json    # Breaker state, reviewer CID, project
      └── <source_cid_2>.json    # Breaker state, reviewer CID, project
```

### Unified Per-Conversation State Schema
Each source conversation stores its state in `<source_cid>.json`:
```json
{
  "source_cid": "7a7f7ba4-8e82-4bfc-8be8-f43535c5af33",
  "project": "/Users/lizeqing/Code/agy-auto-approve",
  "reviewer_conversation_id": "79445b13-e126-4bd2-9a9d-32ddda2d4f46",
  "consecutive_denials": 0,
  "history": ["allow", "allow"],
  "awaiting_approval": false,
  "awaiting_step": null,
  "last_active": "2026-09-13T14:04:49Z"
}
```

---

## 4. Commands

```bash
# Daemon management
agy-auto-approve daemon start                 # Start background daemon
agy-auto-approve daemon status                # Show tracked conversations and PIDs
agy-auto-approve daemon status --json         # Raw JSON status
agy-auto-approve daemon flush                 # Terminate all active reviewer processes
agy-auto-approve daemon stop                  # Stop daemon

# Audit logs
agy-auto-approve logs                         # Show recent approvals
agy-auto-approve logs -f                      # Live stream approvals
agy-auto-approve logs show <id>               # Detailed trace including LLM exchange

# Installation
agy-auto-approve install                      # Install plugin via 'agy plugin install'
```
