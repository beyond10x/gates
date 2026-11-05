//! Security review of `story:bot-delete-branch-atomic`: the installation token that
//! `compare_and_delete_branch` hands to Git reaches the scratch push only through the
//! environment `bot_command` sets, never an argument, a URL, Git's output, a refusal or
//! a trace the caller's environment asks Git for. Every case runs a child entry point of
//! this binary with the environment under test, against local bare repositories, so no
//! case changes this process's environment and nothing reaches the network.
use b10x_gates::delivery::{bot_git, compare_and_delete_branch};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

/// A stand-in for the installation token, distinct enough to find in any output.
const CREDENTIAL: &str = "u4sec-canary-credential-not-a-token";

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("u4sec-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// `git` with no configuration but an identity, with `dir` as its Git directory.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(dir)
        .args([
            "-c",
            "user.name=example",
            "-c",
            "user.email=example@example.invalid",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// A bare remote with `main`, `wave/one` and `keep` at one commit, which is returned.
/// Its `pre-receive` refuses `keep`, so the deletion's refusal path (`git ls-remote`)
/// runs too, and writes the length of the credential the push carried to
/// `<remote>/credential-length`, so a case can tell the credential reached Git without
/// writing it anywhere.
fn remote() -> (tempfile::TempDir, String) {
    let dir = scratch();
    git(dir.path(), &["init", "--quiet", "--bare"]);
    let tree = git(dir.path(), &["mktree"]);
    let tip = git(dir.path(), &["commit-tree", &tree, "-m", "change"]);
    for branch in ["main", "wave/one", "keep"] {
        git(
            dir.path(),
            &["update-ref", &format!("refs/heads/{branch}"), &tip],
        );
    }
    let hook = dir.path().join("hooks/pre-receive");
    fs::create_dir_all(hook.parent().unwrap()).unwrap();
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\nprintf '%s' \"${{#B10X_BOT_TOKEN}}\" > '{}'\n\
             while read old new ref; do [ \"$ref\" = refs/heads/keep ] && exit 1; done\n\
             exit 0\n",
            dir.path().join("credential-length").display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    (dir, tip)
}

/// Run `child` of this test binary with `env`: its `U4SEC ` lines and its stderr.
fn run_child(child: &str, env: &[(&str, &str)]) -> (String, String) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            child,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{child}: {stdout}\n{stderr}");
    let lines = stdout
        .lines()
        // libtest prints `test <name> ... ` before the child's first line.
        .filter_map(|line| line.find("U4SEC ").map(|at| &line[at..]))
        .collect::<Vec<_>>()
        .join("\n");
    (lines, stderr)
}

/// The command a traced argv runs: the program, or for `git` the word after its `-c`
/// pairs.
fn command_of(argv: &Value) -> String {
    let mut words = argv
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str);
    let program = words.next().unwrap_or_default();
    if program.rsplit('/').next() != Some("git") {
        return program.to_string();
    }
    while let Some(word) = words.next() {
        if word != "-c" {
            return word.to_string();
        }
        words.next();
    }
    program.to_string()
}

/// The command of every traced Git process with an event that carries the credential.
fn processes_showing_the_credential(events: &str) -> Vec<String> {
    let events: Vec<Value> = events
        .lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect();
    let sessions: Vec<&str> = events
        .iter()
        .filter(|event| event.to_string().contains(CREDENTIAL))
        .filter_map(|event| event["sid"].as_str())
        .collect();
    events
        .iter()
        .filter(|event| {
            event["event"] == "start"
                && event["sid"]
                    .as_str()
                    .is_some_and(|sid| sessions.contains(&sid))
        })
        .map(|event| command_of(&event["argv"]))
        .collect()
}

#[test]
#[ignore = "child process entry point: run by the_credential_reaches_no_argument_url_output_or_trace and no_caller_trace_setting_shows_the_credential"]
fn child_compare_and_delete() {
    let remote = std::env::var("U4SEC_REMOTE").unwrap();
    let tip = std::env::var("U4SEC_TIP").unwrap();
    for branch in ["wave/one", "keep"] {
        let outcome = compare_and_delete_branch(&remote, branch, &tip, Some(CREDENTIAL))
            .map_err(|error| format!("{error:#}"));
        println!("U4SEC {branch} {outcome:?}");
    }
}

#[test]
#[ignore = "child process entry point: run by the_fetch_verb_shows_the_credential_under_the_same_setting"]
fn child_bot_git_fetch() {
    let root = std::env::var("U4SEC_ROOT").unwrap();
    let remote = std::env::var("U4SEC_REMOTE").unwrap();
    let outcome = bot_git(
        Path::new(&root),
        &["fetch".to_string(), remote, "refs/heads/main".to_string()],
        Some(CREDENTIAL),
    )
    .map_err(|error| format!("{error:#}"));
    println!("U4SEC fetch {outcome:?}");
}

/// Run `child_compare_and_delete` with `env` and Git tracing to files; every text a
/// caller or a file could hold afterwards, by name.
fn delete_traced(env: &[(&str, &str)]) -> Vec<(&'static str, String)> {
    let (remote, tip) = remote();
    let work = scratch();
    let event = work.path().join("trace2.json");
    let trace = work.path().join("trace.txt");
    let mut all = vec![
        ("U4SEC_REMOTE", remote.path().to_str().unwrap()),
        ("U4SEC_TIP", tip.as_str()),
        ("GIT_TRACE2_EVENT", event.to_str().unwrap()),
        ("GIT_TRACE", trace.to_str().unwrap()),
    ];
    all.extend_from_slice(env);
    let (lines, stderr) = run_child("child_compare_and_delete", &all);
    assert!(
        lines.contains("U4SEC wave/one Ok(Deleted)") && lines.contains("U4SEC keep Err("),
        "fixture: the deletion and the refusal did not both run:\n{lines}"
    );
    assert_eq!(
        fs::read_to_string(remote.path().join("credential-length")).unwrap(),
        CREDENTIAL.len().to_string(),
        "fixture: the push did not carry the credential"
    );
    let events = fs::read_to_string(&event).unwrap();
    assert!(
        events.contains("\"push\"") && events.contains("\"ls-remote\""),
        "fixture: the push and the read again were not traced"
    );
    vec![
        ("the outcome and refusal", lines),
        ("Git's output", stderr),
        ("GIT_TRACE", fs::read_to_string(&trace).unwrap()),
        ("GIT_TRACE2_EVENT", events),
    ]
}

/// The safety fact the brief rests on: with tracing on, no argument, URL, child command
/// line, Git output or refusal of the deletion and its read again carries the
/// credential, although the push carried it to Git.
#[test]
fn the_credential_reaches_no_argument_url_output_or_trace() {
    for (name, text) in delete_traced(&[]) {
        assert!(
            !text.contains(CREDENTIAL),
            "the credential appears in {name}: processes {:?}",
            processes_showing_the_credential(&text)
        );
    }
}

/// `GIT_TRACE2_ENV_VARS` in the caller's environment makes every Git process the
/// deletion starts print the named variables into its trace: `B10X_BOT_TOKEN`, the
/// installation token, lands in the trace file. `bot_command` keeps the caller's
/// `GIT_TRACE*` variables, so the scratch push inherits it.
#[test]
fn no_caller_trace_setting_shows_the_credential() {
    for (name, text) in delete_traced(&[("GIT_TRACE2_ENV_VARS", "B10X_BOT_TOKEN")]) {
        assert!(
            !text.contains(CREDENTIAL),
            "the credential appears in {name}, printed by the Git processes {:?}",
            processes_showing_the_credential(&text)
        );
    }
}

/// Origin: the same setting shows the credential through `bot -- fetch`, a path this
/// story did not change (`bot_git` and `bot_command` are as they were before it).
#[test]
fn the_fetch_verb_shows_the_credential_under_the_same_setting() {
    let (remote, _) = remote();
    let root = scratch();
    let init = Command::new("git")
        .args(["init", "--quiet"])
        .arg(root.path())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::null())
        .status()
        .unwrap();
    assert!(init.success(), "fixture: git init failed");
    let work = scratch();
    let event = work.path().join("trace2.json");
    let (lines, _) = run_child(
        "child_bot_git_fetch",
        &[
            ("U4SEC_ROOT", root.path().to_str().unwrap()),
            ("U4SEC_REMOTE", remote.path().to_str().unwrap()),
            ("GIT_TRACE2_EVENT", event.to_str().unwrap()),
            ("GIT_TRACE2_ENV_VARS", "B10X_BOT_TOKEN"),
        ],
    );
    assert!(
        lines.contains("U4SEC fetch Ok(())"),
        "fixture: fetch failed:\n{lines}"
    );
    let events = fs::read_to_string(&event).unwrap();
    assert!(
        !events.contains(CREDENTIAL),
        "the credential appears in GIT_TRACE2_EVENT, printed by the Git processes {:?}",
        processes_showing_the_credential(&events)
    );
}
