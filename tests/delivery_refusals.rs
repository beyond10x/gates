//! Delivery refusals name their cause: the path, the observed state and the fix, or
//! GitHub's own message once it has passed the private-rule matchers.
use b10x_gates::{
    delivery::{self, Github},
    policy::{self, Policy},
    scan::Matchers,
};
use serde_json::json;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn literal() -> String {
    ["synthetic", "restricted", "identifier"].join("-")
}

fn matchers() -> Matchers {
    Matchers::build(&Policy {
        version: 1,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![literal()],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::new(),
        signers: BTreeMap::new(),
        exceptions: vec![],
    })
    .unwrap()
}

fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn refusal(result: anyhow::Result<impl std::fmt::Debug>) -> String {
    format!("{:#}", result.expect_err("expected a refusal"))
}

#[test]
fn protected_read_names_mode_and_fix() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("policy.json");
    fs::write(&file, "{}").unwrap();
    chmod(&file, 0o644);
    let text = refusal(policy::protected_read(&file));
    assert!(text.contains(&file.display().to_string()), "{text}");
    assert!(text.contains("0644"), "{text}");
    assert!(text.contains("0600"), "{text}");
    assert!(text.contains("chmod 600"), "{text}");
}

#[test]
fn protected_read_names_missing_path() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("absent.json");
    let text = refusal(policy::protected_read(&file));
    assert!(text.contains(&file.display().to_string()), "{text}");
    assert!(text.contains("not found"), "{text}");
}

#[test]
fn protected_read_names_writable_parent() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("shared");
    fs::create_dir(&parent).unwrap();
    let file = parent.join("policy.json");
    fs::write(&file, "{}").unwrap();
    chmod(&file, 0o600);
    chmod(&parent, 0o777);
    let text = refusal(policy::protected_read(&file));
    assert!(text.contains(&parent.display().to_string()), "{text}");
    assert!(text.contains("0777"), "{text}");
    assert!(text.contains("chmod go-w"), "{text}");
}

#[test]
fn protect_names_symlink() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("real.json");
    fs::write(&target, "{}").unwrap();
    let link = dir.path().join("link.json");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let text = refusal(policy::protect(&link));
    assert!(text.contains(&link.display().to_string()), "{text}");
    assert!(text.contains("symlink"), "{text}");
}

#[test]
fn private_write_names_writable_output_directory() {
    let dir = tempfile::tempdir().unwrap();
    let parent = dir.path().join("out");
    fs::create_dir(&parent).unwrap();
    chmod(&parent, 0o777);
    let text = refusal(policy::private_write(&parent.join("response.json"), b"{}"));
    assert!(text.contains(&parent.display().to_string()), "{text}");
    assert!(text.contains("0777"), "{text}");
    assert!(text.contains("0700"), "{text}");
}

const DUPLICATE: &str = r#"{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"A pull request already exists for example:branch."}]}"#;

#[test]
fn api_4xx_carries_github_message() {
    let text = delivery::api_failure_for_test(422, DUPLICATE.as_bytes(), &matchers());
    assert!(text.contains("422"), "{text}");
    assert!(text.contains("Validation Failed"), "{text}");
    assert!(
        text.contains("A pull request already exists for example:branch."),
        "{text}"
    );
    assert!(text.contains("PullRequest"), "{text}");
    assert!(text.contains("custom"), "{text}");
}

#[test]
fn api_4xx_withholds_message_matching_private_rule() {
    let body = DUPLICATE.replace("example:branch", &format!("example:{}", literal()));
    let text = delivery::api_failure_for_test(422, body.as_bytes(), &matchers());
    assert!(text.contains("422"), "{text}");
    assert!(
        text.contains("message withheld: it matches a private rule"),
        "{text}"
    );
    assert!(!text.contains(&literal()), "{text}");
    assert!(!text.contains("already exists"), "{text}");
}

#[test]
fn api_4xx_withholds_home_path() {
    let home = ["", "home", "example"].join("/");
    let body = json!({"message": format!("Not Found at {home}/scratch/request.json")}).to_string();
    let text = delivery::api_failure_for_test(404, body.as_bytes(), &matchers());
    assert!(text.contains("404"), "{text}");
    assert!(
        text.contains("message withheld: it matches a private rule"),
        "{text}"
    );
    assert!(!text.contains(&home), "{text}");
}

#[test]
fn api_5xx_and_non_json_render_status_only() {
    let server = delivery::api_failure_for_test(502, DUPLICATE.as_bytes(), &matchers());
    assert!(server.contains("502"), "{server}");
    assert!(!server.contains("Validation Failed"), "{server}");
    let html = delivery::api_failure_for_test(
        405,
        b"<html>Method Not Allowed: example detail</html>",
        &matchers(),
    );
    assert!(html.contains("405"), "{html}");
    assert!(html.contains("Method Not Allowed"), "{html}");
    assert!(!html.contains("example detail"), "{html}");
}

#[test]
fn api_message_strips_control_characters_and_truncates() {
    let long = format!(
        "Pull Request\u{1b}[31m is\nnot mergeable{}",
        "x".repeat(600)
    );
    let body = json!({"message": long}).to_string();
    let text = delivery::api_failure_for_test(405, body.as_bytes(), &matchers());
    assert!(text.contains("405"), "{text}");
    assert!(text.contains("Pull Request[31m isnot mergeable"), "{text}");
    assert!(!text.chars().any(char::is_control), "{text:?}");
    assert!(!text.contains(&"x".repeat(301)), "{text}");
    assert!(text.contains(&"x".repeat(200)), "{text}");
}

#[test]
fn api_success_survives_response_write_failure() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("response.json");
    let response = json!({
        "number": 42,
        "html_url": "https://github.com/example/example/pull/42",
        "body": literal(),
    });
    let report = delivery::api_success_report(
        201,
        &response,
        &output,
        Err(anyhow::anyhow!("disk full")),
        Some(&matchers()),
    )
    .expect("a succeeded remote write is a success");
    assert!(report.stdout.contains("succeeded"), "{}", report.stdout);
    assert!(report.stdout.contains("201"), "{}", report.stdout);
    assert!(report.stdout.contains("42"), "{}", report.stdout);
    assert!(
        report
            .stdout
            .contains("https://github.com/example/example/pull/42"),
        "{}",
        report.stdout
    );
    assert!(!report.stdout.contains(&literal()), "{}", report.stdout);
    let stderr = report.stderr.expect("the write failure is reported");
    assert!(stderr.contains(&output.display().to_string()), "{stderr}");
    assert!(stderr.contains("disk full"), "{stderr}");
}

#[test]
fn api_refuses_bad_output_directory_before_request() {
    let dir = tempfile::tempdir().unwrap();
    let shared = dir.path().join("shared");
    fs::create_dir(&shared).unwrap();
    chmod(&shared, 0o777);
    let config = dir.path().join("config");
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .args([
            "api",
            "--method",
            "GET",
            "--path",
            "/rate_limit",
            "--output",
        ])
        .arg(shared.join("response.json"))
        .env_remove("B10X_GATES_POLICY")
        .env("XDG_CONFIG_HOME", &config)
        .env("B10X_BOT_CONFIG", config.join("absent-bot.json"))
        .env("B10X_BOT_KEY", config.join("absent-key.pem"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains(&shared.display().to_string()), "{stderr}");
    assert!(stderr.contains("0777"), "{stderr}");
    assert!(!stderr.contains("absent-bot.json"), "{stderr}");
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args([
            "-c",
            "user.name=example",
            "-c",
            "user.email=example@example.invalid",
        ])
        .args(args)
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn bot_commit_nothing_staged_is_named() {
    let dir = tempfile::tempdir().unwrap();
    git(
        dir.path(),
        &[
            "-c",
            "init.templateDir=",
            "init",
            "-q",
            "--initial-branch=main",
        ],
    );
    fs::write(dir.path().join("readme"), "initial\n").unwrap();
    git(dir.path(), &["add", "."]);
    git(dir.path(), &["commit", "-qm", "initial"]);
    fs::write(dir.path().join("readme"), "changed but not staged\n").unwrap();
    let github = Github::from_token("synthetic-token".into()).unwrap();
    let text = refusal(github.git(dir.path(), &["commit".into(), "-m".into(), "change".into()]));
    assert!(text.contains("nothing staged"), "{text}");
    assert!(text.contains("exit status 1"), "{text}");
    assert!(!text.contains("synthetic-token"), "{text}");
}

#[test]
fn bot_git_failure_names_verb_and_exit_status() {
    let dir = tempfile::tempdir().unwrap();
    git(
        dir.path(),
        &[
            "-c",
            "init.templateDir=",
            "init",
            "-q",
            "--initial-branch=main",
        ],
    );
    let github = Github::from_token("synthetic-token".into()).unwrap();
    let text = refusal(github.git(dir.path(), &["tag".into(), "v0".into()]));
    assert!(text.contains("bot Git tag failed (exit status"), "{text}");
    assert!(!text.contains("nothing staged"), "{text}");
}

#[test]
fn gh_unsupported_command_is_named() {
    let dir = tempfile::tempdir().unwrap();
    let github = Github::from_token("synthetic-token".into()).unwrap();
    let text = refusal(github.gh(dir.path(), &["auth".into(), "status".into()]));
    assert!(text.contains("auth"), "{text}");
    assert!(
        text.contains("release, pr, run, workflow, api, repo"),
        "{text}"
    );
}
