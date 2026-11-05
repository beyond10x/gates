//! `story:token-env-error-value`: a credential or policy variable that is set but not
//! Unicode is refused naming the variable, and no form of the refusal (`{}`, `{:#}`,
//! `{:?}`) nor any output of the binary carries a byte of its value. The standard
//! library's `VarError::NotUnicode` carries the value in its `Display` and `Debug`, so
//! `std::env::var(..).context(..)` would put it into the full error. A missing variable
//! is still refused naming the variable.
//!
//! Each site reads the process environment, so each library case runs its read in a
//! child process of this test binary with the variable set there.
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    policy::{Policy, Repository},
    published_merge::AuthenticatedRead,
};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    path::Path,
    process::{Command, Output},
};

/// The two valid runs of the value, either side of one byte that is not UTF-8. Built at
/// run time so the source carries no credential-shaped literal.
fn runs() -> [String; 2] {
    [
        [["gh", "p_"].concat().as_str(), "Zq7Lm4", "Rt9Kp2"].concat(),
        ["Wx4Vb6", "Nc8Jd0", "Hf3Gs5", "Ty1Qa8"].concat(),
    ]
}

fn value() -> OsString {
    let [before, after] = runs();
    let mut bytes = before.into_bytes();
    bytes.push(0xff);
    bytes.extend_from_slice(after.as_bytes());
    OsStr::from_bytes(&bytes).to_owned()
}

/// No four consecutive bytes of either run, and no rendering of the invalid byte.
fn assert_no_part(text: &str) {
    for run in runs() {
        for part in run.as_bytes().windows(4) {
            let part = std::str::from_utf8(part).unwrap();
            assert!(!text.contains(part), "carries {part:?}: {text}");
        }
    }
    for rendering in ["\u{fffd}", "\\xFF", "\\xff", "\\u{ff}"] {
        assert!(!text.contains(rendering), "carries {rendering:?}: {text}");
    }
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Run the child entry point `name` of this binary with `variable` set to `value`, or
/// removed when `value` is `None`; the child prints every form of its error.
fn child(name: &str, variable: &str, value: Option<&OsStr>) -> String {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        name,
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    command.env_remove(variable);
    if let Some(value) = value {
        command.env(variable, value);
    }
    let output = command.output().unwrap();
    let text = text(&output);
    assert!(output.status.success(), "child failed: {text}");
    assert!(text.contains("FORMS-END"), "child printed no error: {text}");
    text
}

fn print_forms(error: &anyhow::Error) {
    println!("FORMS-BEGIN\n{error}\n{error:#}\n{error:?}\nFORMS-END");
}

#[test]
#[ignore = "child process entry point: run by push_evidence_names_the_bot_token_never_its_value"]
fn push_evidence_child_entry_point() {
    let error = b10x_gates::delivery::PushEvidence
        .get("/repos/example/repository/pulls/1")
        .expect_err("push evidence read without a usable credential");
    print_forms(&error);
}

#[test]
fn push_evidence_names_the_bot_token_never_its_value() {
    let output = child(
        "push_evidence_child_entry_point",
        "B10X_BOT_TOKEN",
        Some(&value()),
    );
    assert!(output.contains("B10X_BOT_TOKEN is not Unicode"), "{output}");
    assert_no_part(&output);
    let output = child("push_evidence_child_entry_point", "B10X_BOT_TOKEN", None);
    assert!(output.contains("B10X_BOT_TOKEN is not set"), "{output}");
}

const REPOSITORY: &str = "example/repository";

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", BOT_NAME)
        .env("GIT_AUTHOR_EMAIL", BOT_EMAIL)
        .env("GIT_COMMITTER_NAME", BOT_NAME)
        .env("GIT_COMMITTER_EMAIL", BOT_EMAIL)
        .output()
        .unwrap();
    assert!(output.status.success(), "Git fixture failed: {output:?}");
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn policy(baseline: &str) -> Policy {
    Policy {
        version: 2,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::from([(
            REPOSITORY.into(),
            Repository {
                id: "123".into(),
                baseline: baseline.into(),
            },
        )]),
        signers: BTreeMap::new(),
        exceptions: vec![],
    }
}

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("token-env-error-value-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

#[test]
#[ignore = "child process entry point: run by ci_fetch_names_the_workflow_token_never_its_value"]
fn ci_fetch_child_entry_point() {
    // A local repository stands in for GitHub, so a fetch that dropped the unreadable
    // credential and went on anonymously would succeed here.
    let remote = scratch();
    let root = remote.path();
    git(
        root,
        &[
            "-c",
            "init.templateDir=",
            "init",
            "-q",
            "--initial-branch=main",
        ],
    );
    std::fs::write(root.join("readme"), b"initial safe bytes\n").unwrap();
    git(root, &["add", "--", "readme"]);
    git(root, &["commit", "-qm", "readme"]);
    let head = git(root, &["rev-parse", "HEAD"]);
    let work = scratch();
    let event = work.path().join("event.json");
    let payload = serde_json::json!({
        "after": head,
        "ref": "refs/heads/main",
        "repository": {"id": 123, "full_name": REPOSITORY}
    });
    std::fs::write(&event, serde_json::to_vec(&payload).unwrap()).unwrap();
    let source = root.display().to_string();
    let error = b10x_gates::delivery::ci_candidate_from(
        &policy(&head),
        &event,
        &work.path().join("candidate.git"),
        |_| source.clone(),
    )
    .err()
    .expect("candidate fetched without a usable workflow credential");
    print_forms(&error);
}

#[test]
fn ci_fetch_names_the_workflow_token_never_its_value() {
    let output = child("ci_fetch_child_entry_point", "GITHUB_TOKEN", Some(&value()));
    assert!(output.contains("GITHUB_TOKEN is not Unicode"), "{output}");
    assert_no_part(&output);
}

/// `b10x-gates ci` with a valid JSON policy, so it gets past the policy, and `env`.
fn ci(env: &[(&str, &OsStr)]) -> String {
    let home = scratch();
    let mut command = Command::new(env!("CARGO_BIN_EXE_b10x-gates"));
    command
        .args(["ci", "--event", "/nonexistent/event.json", "--objects"])
        .arg(home.path().join("objects"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home.path())
        .env("TMPDIR", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env(
            "B10X_GATES_POLICY_JSON",
            serde_json::to_string(&policy(&"0".repeat(40))).unwrap(),
        );
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    assert!(!output.status.success(), "ci succeeded: {output:?}");
    text(&output)
}

#[test]
fn ci_names_the_workflow_token_never_its_value() {
    let output = ci(&[("GITHUB_TOKEN", &value())]);
    assert!(output.contains("GITHUB_TOKEN is not Unicode"), "{output}");
    assert_no_part(&output);
    let output = ci(&[]);
    assert!(output.contains("GITHUB_TOKEN is not set"), "{output}");
}

#[test]
fn ci_names_each_policy_variable_never_its_value() {
    for variable in ["B10X_GATES_POLICY_GZ", "B10X_GATES_POLICY_JSON"] {
        let output = ci(&[(variable, &value())]);
        assert!(
            output.contains(&format!("{variable} is not Unicode")),
            "{output}"
        );
        assert_no_part(&output);
    }
}
