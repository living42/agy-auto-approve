use agy_auto_approve::{
    config, parser,
    pipeline::{ConversationState, blacklist, read_only},
    reviewer::{ReviewerPool, parse},
};
use serde_json::json;
use std::time::Duration;

#[test]
fn bash_command_parsing() {
    for (command, expected) in [
        (
            "mise run local:down 2>&1; sleep 2; mise run test:e2e 2>&1",
            vec![
                "mise run local:down 2>&1",
                "sleep 2",
                "mise run test:e2e 2>&1",
            ],
        ),
        (
            "cargo build -p agent && (cd tests/deploy && cargo build)",
            vec!["cargo build -p agent", "cd tests/deploy", "cargo build"],
        ),
        (
            "REMOVE_OLD_STATE=y PATH=\"/opt/bin:$PATH\" ./start.sh",
            vec!["./start.sh"],
        ),
        (
            "echo $(which python) && echo `whoami`",
            vec![
                "echo $(which python)",
                "which python",
                "echo `whoami`",
                "whoami",
            ],
        ),
        (
            "cat << 'EOF' > test.ts\nimport foo from 'bar';\nEOF\nnpm test",
            vec![
                "cat << 'EOF' > test.ts\nimport foo from 'bar';\nEOF",
                "npm test",
            ],
        ),
        (
            "$( (cmd1 | cmd2) > /dev/null )",
            vec!["$( (cmd1 | cmd2) > /dev/null )", "cmd1", "cmd2"],
        ),
    ] {
        assert_eq!(parser::commands(command), expected, "{command}");
    }
}

#[test]
fn deterministic_policies() {
    for cmd in [
        "rm -rf /",
        "rm -rf /*",
        "rm -rf ~",
        "rm -rf /path/.git",
        "mkfs.ext4 /dev/sda1",
        ":(){ :|:& };:",
        "echo $(rm -rf /)",
        "(rm -rf /)",
        "`rm -rf /`",
        "echo $(rm -rf $HOME)",
    ] {
        assert!(blacklist(cmd).is_some(), "{cmd}");
    }
    for cmd in [
        "ls -la",
        "git status",
        "cargo build",
        "echo 'Hello world'",
        "arm-none-eabi-gcc main.c",
    ] {
        assert!(blacklist(cmd).is_none(), "{cmd}");
    }
    assert!(read_only("view_file"));
    assert!(!read_only("run_command"));
}

#[test]
fn tolerant_review_fails_closed() {
    for raw in [
        "",
        " ",
        "not JSON",
        "[]",
        "null",
        "{}",
        "{\"outcome\":\"maybe\"}",
    ] {
        assert_eq!(parse(raw).outcome, "deny");
    }
    assert_eq!(
        parse("text ```json\n{\"outcome\":\"allow\"}\n``` trailing").outcome,
        "allow"
    );
    assert_eq!(
        parse("prefix {\"decision\":\" ALLOW \"} suffix").risk_level,
        "low"
    );
    assert_eq!(parse("{\"outcome\":\"force_ask\"}").outcome, "force_ask");
}

#[test]
fn unified_conversation_state_persistence() {
    let dir = tempfile::tempdir().unwrap();
    let cid = "test_conversation_123";
    {
        let mut state = ConversationState::open(dir.path(), cid).unwrap();
        assert_eq!(state.source_cid(), cid);
        assert_eq!(state.consecutive_denials(), 0);
        assert!(state.reviewer_cid().is_none());
        assert_eq!(state.project(), "");

        // Set metadata
        state.set_reviewer_cid("rev-4f2a-8b1c").unwrap();
        state.set_project("/Users/lizeqing/Code/project1").unwrap();

        for _ in 0..3 {
            assert!(state.tripped().is_none());
            state.record("deny").unwrap();
        }
        assert!(state.tripped().is_some());
    }

    // Verify file name has no cb_ prefix
    let expected_file = dir.path().join(format!("{cid}.json"));
    assert!(expected_file.exists());
    assert!(!dir.path().join(format!("cb_{cid}.json")).exists());

    // Reopen and check persisted state
    let mut reopened = ConversationState::open(dir.path(), cid).unwrap();
    assert!(reopened.tripped().is_some());
    assert_eq!(reopened.reviewer_cid().as_deref(), Some("rev-4f2a-8b1c"));
    assert_eq!(reopened.project(), "/Users/lizeqing/Code/project1");

    reopened.record("allow").unwrap();
    assert!(reopened.tripped().is_none());
    assert_eq!(reopened.consecutive_denials(), 0);

    reopened.record("deny").unwrap();
    assert!(reopened.tripped().unwrap().contains("4/5"));
}

#[test]
fn conversation_state_post_tool_use_reset() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = ConversationState::open(dir.path(), "session").unwrap();
    for _ in 0..3 {
        b.record("deny").unwrap();
    }
    assert!(b.tripped().is_some());

    // Mark force ask awaiting approval for step 10
    b.mark_force_ask(Some(10)).unwrap();
    assert!(b.tripped().is_some());

    // PostToolUse for unrelated step does not reset
    assert!(!b.on_post_tool_use(Some(99)).unwrap());
    assert!(b.tripped().is_some());

    // PostToolUse for the approved step resets breaker
    assert!(b.on_post_tool_use(Some(10)).unwrap());
    assert!(b.tripped().is_none());

    drop(b);

    // Persisted state also shows breaker is cleared
    let b_reopened = ConversationState::open(dir.path(), "session").unwrap();
    assert!(b_reopened.tripped().is_none());
}

#[test]
fn invalid_outcome_cannot_fall_back_to_allow() {
    for invalid in [
        json!(42),
        json!(true),
        json!(["allow"]),
        json!({"value":"allow"}),
    ] {
        assert_eq!(
            parse(&json!({"outcome":invalid,"decision":"allow"}).to_string()).outcome,
            "deny"
        );
    }
    for absent in [
        json!(null),
        json!(false),
        json!(0),
        json!(""),
        json!([]),
        json!({}),
    ] {
        assert_eq!(
            parse(&json!({"outcome":absent,"decision":"allow"}).to_string()).outcome,
            "allow"
        );
    }
}

#[test]
fn shell_syntax_regressions() {
    for (command, expected) in [
        ("A=1", vec![]),
        ("A=1\nB=2\necho ready", vec!["echo ready"]),
        ("A=1 \\\n B=2 \\\n ./build.sh", vec!["./build.sh"]),
        (
            "echo <(cat /tmp/x)",
            vec!["echo <(cat /tmp/x)", "cat /tmp/x"],
        ),
        ("for x in a b; do echo \"$x\"; done", vec!["echo \"$x\""]),
        ("if test -f x; then cat x; fi", vec!["test -f x", "cat x"]),
        (
            "cat output.log | grep ERROR | wc -l",
            vec!["cat output.log", "grep ERROR", "wc -l"],
        ),
        ("killall worker || true", vec!["killall worker", "true"]),
        (
            "git commit -m 'semicolon ; and && stay quoted'",
            vec!["git commit -m 'semicolon ; and && stay quoted'"],
        ),
        (
            "echo 'import sys;sys.exit(0)' > /tmp/helper.py",
            vec!["echo 'import sys;sys.exit(0)' > /tmp/helper.py"],
        ),
    ] {
        assert_eq!(parser::commands(command), expected, "{command}");
    }
    for command in [
        "cat << EOF > file.txt\nline 1\nEOF",
        "cat << \"DELIM\" > file.txt\nline 2\nDELIM",
        "cat <<- 'EOF' > file.txt\n\tline 3\n\tEOF",
        "cat <<'EOF' >> main.css\n.foo { color: red; }\nEOF",
    ] {
        assert_eq!(parser::commands(command), [command]);
    }
    assert_eq!(parser::clean("echo (foo)"), "echo (foo)");
    assert!(parser::commands("").is_empty());
}

#[test]
fn agy_bin_and_paths_resolution() {
    unsafe {
        std::env::set_var("AGY_BIN", "/custom/bin/agy");
        std::env::set_var("AGY_AUTO_APPROVE_DIR", "/custom/base");
        std::env::set_var("AGY_APPROVER_STATE_DIR", "/custom/base/state");
        std::env::set_var("AGY_APPROVER_SOCKET", "/custom/base/approver.sock");
    }

    assert_eq!(
        config::agy_bin(),
        std::path::PathBuf::from("/custom/bin/agy")
    );
    assert_eq!(config::base_dir(), std::path::PathBuf::from("/custom/base"));
    assert_eq!(config::log_dir(), std::path::PathBuf::from("/custom/base"));
    assert_eq!(
        config::state_dir(),
        std::path::PathBuf::from("/custom/base/state")
    );
    assert_eq!(
        config::socket_path(),
        std::path::PathBuf::from("/custom/base/approver.sock")
    );

    unsafe {
        std::env::remove_var("AGY_BIN");
        std::env::remove_var("AGY_AUTO_APPROVE_DIR");
        std::env::remove_var("AGY_APPROVER_STATE_DIR");
        std::env::remove_var("AGY_APPROVER_SOCKET");
    }
}

#[test]
fn reviewer_pool_reclaim_and_flush_and_status() {
    let mut pool = ReviewerPool::default();
    assert_eq!(pool.flush_all(), 0);
    assert_eq!(pool.reclaim_idle(Duration::from_secs(600)), 0);

    // Test status snapshot reads state files
    let dir = tempfile::tempdir().unwrap();
    unsafe {
        std::env::set_var("AGY_APPROVER_STATE_DIR", dir.path().to_str().unwrap());
    }

    let mut state1 = ConversationState::open(dir.path(), "conv_1").unwrap();
    state1.set_project("/project/one").unwrap();
    state1.set_reviewer_cid("rev-1").unwrap();

    let snapshot = pool.status_snapshot();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].source_cid, "conv_1");
    assert_eq!(snapshot[0].reviewer_cid.as_deref(), Some("rev-1"));
    assert_eq!(snapshot[0].project, "/project/one");
    assert!(snapshot[0].process_state.contains("Reclaimed"));

    unsafe {
        std::env::remove_var("AGY_APPROVER_STATE_DIR");
    }
}
