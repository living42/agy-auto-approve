use agy_auto_approve::{
    config, parser,
    pipeline::{
        ConversationState, is_subpath, is_workspace_edit, is_workspace_file_op, normalize_path,
    },
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
fn workspace_default_file_policies() {
    let ws = "/Users/test/Code/project";

    // Read operations under workspace -> allowed
    for (tool, arg_key) in [
        ("view_file", "AbsolutePath"),
        ("read_file", "path"),
        ("grep_search", "SearchPath"),
        ("find_by_name", "SearchDirectory"),
        ("list_dir", "DirectoryPath"),
    ] {
        let payload = json!({
            "toolCall": {
                "name": tool,
                "args": { arg_key: format!("{ws}/src/main.rs") }
            },
            "workspacePaths": [ws]
        });
        assert!(
            is_workspace_file_op(&payload),
            "tool {tool} should be allowed under workspace"
        );
    }

    // Write operations under workspace -> allowed
    for (tool, arg_key) in [
        ("write_to_file", "TargetFile"),
        ("write_file", "path"),
        ("replace_file_content", "TargetFile"),
        ("edit_file", "target_file"),
        ("apply_patch", "FilePath"),
    ] {
        let payload = json!({
            "toolCall": {
                "name": tool,
                "args": { arg_key: format!("{ws}/src/lib.rs") }
            },
            "workspacePaths": [ws]
        });
        assert!(
            is_workspace_file_op(&payload),
            "tool {tool} should be allowed under workspace"
        );
    }

    // Non-file tools are not workspace file operations
    for (tool, args) in [
        ("run_command", json!({"CommandLine": "ls -la"})),
        ("read_url_content", json!({"Url": "https://example.com"})),
        ("search_web", json!({"query": "rust"})),
        ("manage_task", json!({"Action": "list"})),
    ] {
        let payload = json!({
            "toolCall": {
                "name": tool,
                "args": args
            },
            "workspacePaths": [ws]
        });
        assert!(
            !is_workspace_file_op(&payload),
            "tool {tool} should not be a workspace file op"
        );
    }
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

#[test]
fn path_normalization_and_subpath() {
    use std::path::Path;

    let p = normalize_path(Path::new("/a/b/../c/./d"));
    assert_eq!(p, std::path::PathBuf::from("/a/c/d"));

    let base = Path::new("/workspace/project");
    assert!(is_subpath(
        Path::new("/workspace/project/src/main.rs"),
        base
    ));
    assert!(is_subpath(
        Path::new("/workspace/project/sub/dir/file.txt"),
        base
    ));
    assert!(is_subpath(Path::new("/workspace/project"), base));

    // Traversal escaping base directory
    assert!(!is_subpath(
        Path::new("/workspace/project/../../etc/passwd"),
        base
    ));
    assert!(!is_subpath(Path::new("/workspace/other"), base));
    assert!(!is_subpath(Path::new("/etc/hosts"), base));
}

#[test]
fn workspace_file_edit_whitelist() {
    let ws = "/Users/test/workspace/myproject";
    let artifact_dir = "/Users/test/.gemini/antigravity-cli/brain/conv-123";

    // 1. write_to_file in workspace -> allowed
    let payload = json!({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": format!("{ws}/src/lib.rs")
            }
        },
        "workspacePaths": [ws]
    });
    assert!(is_workspace_edit(&payload));
    assert!(is_workspace_file_op(&payload));

    // 2. replace_file_content in nested workspace folder -> allowed
    let payload = json!({
        "toolCall": {
            "name": "replace_file_content",
            "args": {
                "TargetFile": format!("{ws}/tests/sub/test.rs")
            }
        },
        "workspacePaths": [ws]
    });
    assert!(is_workspace_edit(&payload));
    assert!(is_workspace_file_op(&payload));

    // 3. edit_file and apply_patch with target_file / path variations -> allowed
    let payload = json!({
        "toolCall": {
            "name": "edit_file",
            "args": {
                "target_file": format!("{ws}/README.md")
            }
        },
        "workspacePaths": [ws]
    });
    assert!(is_workspace_edit(&payload));
    assert!(is_workspace_file_op(&payload));

    let payload = json!({
        "toolCall": {
            "name": "apply_patch",
            "args": {
                "FilePath": format!("{ws}/Cargo.toml")
            }
        },
        "workspacePaths": [ws]
    });
    assert!(is_workspace_edit(&payload));
    assert!(is_workspace_file_op(&payload));

    // 4. write_to_file in artifactDirectoryPath -> allowed
    let payload = json!({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": format!("{artifact_dir}/plan.md")
            }
        },
        "workspacePaths": [ws],
        "artifactDirectoryPath": artifact_dir
    });
    assert!(is_workspace_edit(&payload));
    assert!(is_workspace_file_op(&payload));

    // 5. Relative target path inside workspace -> allowed
    let payload = json!({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "src/new_module.rs"
            }
        },
        "workspacePaths": [ws]
    });
    assert!(is_workspace_edit(&payload));
    assert!(is_workspace_file_op(&payload));

    // 6. Path traversal attempting escape -> rejected
    let payload = json!({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": format!("{ws}/../../etc/passwd")
            }
        },
        "workspacePaths": [ws]
    });
    assert!(!is_workspace_edit(&payload));
    assert!(!is_workspace_file_op(&payload));

    // 7. Directly targeting .git directory -> rejected
    let payload = json!({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": format!("{ws}/.git/hooks/pre-commit")
            }
        },
        "workspacePaths": [ws]
    });
    assert!(!is_workspace_edit(&payload));
    assert!(!is_workspace_file_op(&payload));

    let payload = json!({
        "toolCall": {
            "name": "replace_file_content",
            "args": {
                "TargetFile": format!("{ws}/.git/config")
            }
        },
        "workspacePaths": [ws]
    });
    assert!(!is_workspace_edit(&payload));
    assert!(!is_workspace_file_op(&payload));

    // 8. File modification outside workspace -> rejected
    let payload = json!({
        "toolCall": {
            "name": "write_to_file",
            "args": {
                "TargetFile": "/etc/hosts"
            }
        },
        "workspacePaths": [ws]
    });
    assert!(!is_workspace_edit(&payload));
    assert!(!is_workspace_file_op(&payload));

    // 9. Non-edit tools -> rejected
    let payload = json!({
        "toolCall": {
            "name": "run_command",
            "args": {
                "CommandLine": "echo hello"
            }
        },
        "workspacePaths": [ws]
    });
    assert!(!is_workspace_edit(&payload));
    assert!(!is_workspace_file_op(&payload));

    // 10. Read tool under workspace -> is_workspace_file_op is true, but is_workspace_edit is false
    let payload = json!({
        "toolCall": {
            "name": "view_file",
            "args": {
                "AbsolutePath": format!("{ws}/src/lib.rs")
            }
        },
        "workspacePaths": [ws]
    });
    assert!(is_workspace_file_op(&payload));
    assert!(!is_workspace_edit(&payload));
}

#[test]
fn eval_timeout_configuration() {
    unsafe {
        std::env::remove_var("AGY_AUTO_APPROVE_TIMEOUT");
    }
    assert_eq!(config::eval_timeout(), 120);

    unsafe {
        std::env::set_var("AGY_AUTO_APPROVE_TIMEOUT", "90");
    }
    assert_eq!(config::eval_timeout(), 90);

    unsafe {
        std::env::remove_var("AGY_AUTO_APPROVE_TIMEOUT");
    }
}

#[test]
fn permission_syntax_parsing() {
    use agy_auto_approve::config::{PermissionAction, PermissionRule};

    let r1 = PermissionRule::parse("command(git*)").expect("parse git*");
    assert_eq!(r1.action, PermissionAction::Command);
    assert!(r1.matches_single_command("git status"));
    assert!(r1.matches_single_command("git commit -m 'test'"));
    assert!(!r1.matches_single_command("curl https://evil.com"));

    let r2 = PermissionRule::parse("unsandboxed(ls)").expect("parse unsandboxed(ls)");
    assert_eq!(r2.action, PermissionAction::Unsandboxed);
    assert!(r2.matches_single_command("ls"));
    assert!(r2.matches_single_command("ls -la"));
    assert!(!r2.matches_single_command("lsof -i :8080"));

    let r3 = PermissionRule::parse("command(regex:^npm run (test|build)$)").expect("parse regex");
    assert!(r3.matches_single_command("npm run test"));
    assert!(r3.matches_single_command("npm run build"));
    assert!(!r3.matches_single_command("npm run publish"));

    let r4 = PermissionRule::parse("read_file(/tmp/safe/*)").expect("parse read_file");
    assert_eq!(r4.action, PermissionAction::ReadFile);
    assert!(r4.matches_path(std::path::Path::new("/tmp/safe/a.txt"), false));
    assert!(!r4.matches_path(std::path::Path::new("/tmp/safe/a.txt"), true));

    let r5 = PermissionRule::parse("write_file(/tmp/safe/*)").expect("parse write_file");
    assert_eq!(r5.action, PermissionAction::WriteFile);
    assert!(r5.matches_path(std::path::Path::new("/tmp/safe/b.txt"), true));
    // WriteFile implicitly allows read_file
    assert!(r5.matches_path(std::path::Path::new("/tmp/safe/b.txt"), false));

    let r6 = PermissionRule::parse("read_url(github.com)").expect("parse read_url");
    assert_eq!(r6.action, PermissionAction::ReadUrl);
    assert!(r6.matches_url("https://github.com/jjyr/agy-auto-approve"));
    assert!(!r6.matches_url("https://google.com"));

    let r7 = PermissionRule::parse("finish").expect("parse bare tool name");
    assert!(r7.matches_tool_name("finish"));
    assert!(!r7.matches_tool_name("run_command"));
}

#[test]
fn config_yaml_deserialization_and_aliases() {
    let yaml = r#"
module: "gemini-2.5-pro"
thinking_effort: "high"
evalute_timeout: 180

deny:
  - "command(rm -rf /*)"
  - "write_file(/etc/*)"

allow:
  - "command(git*)"
  - "unsandboxed(ls)"

circuit_breaker:
  max_consecutive_denials: 5
  recent_denials_window: 7
  recent_denials_threshold: 6

daemon:
  idle_timeout: 3600
  worker_reclaim_timeout: 1200
"#;

    let cfg: agy_auto_approve::config::Config = serde_yaml::from_str(yaml).unwrap();
    assert_eq!(cfg.model, "gemini-2.5-pro");
    assert_eq!(cfg.effort, "high");
    assert_eq!(cfg.timeout, 180);
    assert_eq!(cfg.deny.0.len(), 2);
    assert_eq!(cfg.allow.0.len(), 2);
    assert_eq!(cfg.circuit_breaker.max_consecutive_denials, 5);
    assert_eq!(cfg.circuit_breaker.recent_denials_window, 7);
    assert_eq!(cfg.circuit_breaker.recent_denials_threshold, 6);
    assert_eq!(cfg.daemon.idle_timeout, 3600);
    assert_eq!(cfg.daemon.worker_reclaim_timeout, 1200);
}

#[test]
fn permission_matching_and_precedence() {
    use agy_auto_approve::config::{PermissionOutcome, check_permissions, reset_cache};

    let dir = tempfile::tempdir().unwrap();
    let config_path = dir.path().join("config.yaml");
    std::fs::write(
        &config_path,
        r#"
deny:
  - "command(rm -rf /*)"
  - "command(curl*)"
  - "write_file(/etc/*)"

allow:
  - "command(git*)"
  - "command(cargo *)"
  - "unsandboxed(ls)"
  - "read_file(/tmp/*)"
"#,
    )
    .unwrap();

    unsafe {
        std::env::set_var("AGY_AUTO_APPROVE_CONFIG", &config_path);
    }
    reset_cache();

    // 1. Matched by Deny
    let deny_call = json!({"CommandLine": "rm -rf /"});
    assert!(matches!(
        check_permissions("run_command", &deny_call),
        Some(PermissionOutcome::Deny(_))
    ));

    // 2. Matched by Allow
    let allow_call = json!({"CommandLine": "git status"});
    assert!(matches!(
        check_permissions("run_command", &allow_call),
        Some(PermissionOutcome::Allow(_))
    ));

    // 3. Deny takes precedence when compound command contains both
    let compound_deny = json!({"CommandLine": "git status && rm -rf /"});
    assert!(matches!(
        check_permissions("run_command", &compound_deny),
        Some(PermissionOutcome::Deny(_))
    ));

    // 4. Compound command where all parts are allowed -> Allow
    let compound_allow = json!({"CommandLine": "git status && cargo check"});
    assert!(matches!(
        check_permissions("run_command", &compound_allow),
        Some(PermissionOutcome::Allow(_))
    ));

    // 5. Compound command where one part is unknown -> None (sent to LLM)
    let compound_unknown = json!({"CommandLine": "git status && node script.js"});
    assert_eq!(check_permissions("run_command", &compound_unknown), None);

    // 6. Write file denied
    let write_etc = json!({"TargetFile": "/etc/hosts"});
    assert!(matches!(
        check_permissions("write_to_file", &write_etc),
        Some(PermissionOutcome::Deny(_))
    ));

    unsafe {
        std::env::remove_var("AGY_AUTO_APPROVE_CONFIG");
    }
    reset_cache();
}
