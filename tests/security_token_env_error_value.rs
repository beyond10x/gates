//! Security review of `story:token-env-error-value`: boundary cases the unit's own tests do
//! not measure. A credential variable that is set but empty is no usable credential, so it
//! is refused naming the variable, as a missing one is, and `ci` fetches nothing for it
//! (`main.rs`: "Read before the fetch, so a run without a usable workflow token fetches
//! nothing"). And the one line `main` prints for a refused push evidence read, the
//! top-level text `published_merge::ReadFailure` takes from the inner error, names the
//! variable that could not be read.
//!
//! Each library case reads the process environment, so it runs in a child process of this
//! test binary with the variable set there.
use b10x_gates::{
    policy::{Policy, Repository},
    published_merge::AuthenticatedRead,
};
use std::{
    collections::BTreeMap,
    ffi::{OsStr, OsString},
    os::unix::ffi::OsStrExt,
    process::{Command, Output},
};

/// A token-shaped value with one byte that is not UTF-8. Built at run time so the source
/// carries no credential-shaped literal.
fn not_unicode() -> OsString {
    let mut bytes = [["gh", "p_"].concat().as_str(), "Vb5Nm2", "Qw8Er1"]
        .concat()
        .into_bytes();
    bytes.push(0xfe);
    bytes.extend_from_slice(b"Ty6Ui3Op0As4");
    OsStr::from_bytes(&bytes).to_owned()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// Run the child entry point `name` with `variable` set to `value`, or removed when
/// `value` is `None`; returns what the child printed between `LINE-BEGIN` and `LINE-END`.
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
    let begin = text.find("LINE-BEGIN\n").expect("child printed no error");
    let end = text.find("\nLINE-END").expect("child printed no error");
    text[begin + "LINE-BEGIN\n".len()..end].to_owned()
}

fn push_evidence_error() -> anyhow::Error {
    b10x_gates::delivery::PushEvidence
        .get("/repos/example/repository/pulls/1")
        .expect_err("push evidence read without a usable credential")
}

#[test]
#[ignore = "child process entry point: run by an_empty_bot_token_is_refused_naming_it"]
fn push_evidence_full_child_entry_point() {
    let error = push_evidence_error();
    println!("LINE-BEGIN\n{error:#}\nLINE-END");
}

#[test]
#[ignore = "child process entry point: run by the_line_main_prints_names_the_bot_token"]
fn push_evidence_line_child_entry_point() {
    let error = push_evidence_error();
    println!("LINE-BEGIN\n{error}\nLINE-END");
}

/// An empty `B10X_BOT_TOKEN` is as unusable as a missing one: the refusal names it.
#[test]
fn an_empty_bot_token_is_refused_naming_it() {
    let full = child(
        "push_evidence_full_child_entry_point",
        "B10X_BOT_TOKEN",
        Some(OsStr::new("")),
    );
    assert!(full.contains("B10X_BOT_TOKEN"), "{full}");
}

/// `main` prints only the top-level text of a refusal, and a refused evidence read
/// (`ReadFailure`) carries the inner error's top-level text, so that text is what names
/// the unreadable variable to the person whose push Git refused.
#[test]
fn the_line_main_prints_names_the_bot_token() {
    for value in [None, Some(not_unicode())] {
        let line = child(
            "push_evidence_line_child_entry_point",
            "B10X_BOT_TOKEN",
            value.as_deref(),
        );
        assert!(line.contains("B10X_BOT_TOKEN"), "{value:?}: {line}");
    }
}

const REPOSITORY: &str = "example/repository";

fn policy() -> Policy {
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
                baseline: "0".repeat(40),
            },
        )]),
        signers: BTreeMap::new(),
        exceptions: vec![],
    }
}

/// `b10x-gates ci` with a valid JSON policy, an event file that does not exist, and
/// `GITHUB_TOKEN` set to `token`. A run that went past the token to the fetch reports the
/// event instead of the variable.
fn ci(token: &OsStr) -> String {
    let home = tempfile::Builder::new()
        .prefix("security-token-env-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .args(["ci", "--event", "/nonexistent/event.json", "--objects"])
        .arg(home.path().join("objects"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home.path())
        .env("TMPDIR", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env(
            "B10X_GATES_POLICY_JSON",
            serde_json::to_string(&policy()).unwrap(),
        )
        .env("GITHUB_TOKEN", token)
        .output()
        .unwrap();
    assert!(!output.status.success(), "ci succeeded: {output:?}");
    text(&output)
}

/// An empty `GITHUB_TOKEN` is no usable workflow token: `ci` refuses it naming the
/// variable before it reads the event or fetches anything.
#[test]
fn ci_with_an_empty_workflow_token_fetches_nothing_and_names_it() {
    let output = ci(OsStr::new(""));
    assert!(output.contains("GITHUB_TOKEN"), "{output}");
}
