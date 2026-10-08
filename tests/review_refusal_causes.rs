//! Security review of the refusal-causes wave: conformance cases for the bot argument
//! check, the nothing-staged diagnosis and the vetting of GitHub's text.
use b10x_gates::{
    bot_args::check,
    delivery::{self, Github},
    policy::Policy,
    scan::Matchers,
};
use serde_json::json;
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::Path, process::Command};

fn args(line: &str) -> Vec<String> {
    line.split_whitespace().map(String::from).collect()
}

fn literal() -> String {
    ["synthetic", "restricted", "identifier"].join("-")
}

fn short_literal() -> String {
    ["cu", "st"].join("")
}

fn matchers() -> Matchers {
    Matchers::build(&Policy {
        version: 1,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![literal(), short_literal()],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::new(),
        signers: BTreeMap::new(),
        exceptions: vec![],
    })
    .unwrap()
}

// ---- Invariant 5: bot argument check ----

/// Git's option parser takes any unique prefix; `--m` is unique for `git push` and
/// means `--mirror`, which deletes every remote branch absent locally.
#[test]
fn push_mirror_single_letter_prefix_is_refused() {
    assert!(
        check(&args("push --m origin"), None).is_err(),
        "`push --m origin` (= --mirror) passed the bot argument check"
    );
}

/// `git commit -nm x` is `-n -m x`: `-n` is `--no-verify` inside a short cluster.
#[test]
fn no_verify_in_short_cluster_is_refused() {
    assert!(
        check(&args("commit -nm change"), None).is_err(),
        "`commit -nm` (skips pre-commit and commit-msg hooks) passed the check"
    );
}

/// `--no-verif` is a unique prefix of `--no-verify` for both commit and push.
#[test]
fn no_verify_abbreviation_is_refused() {
    for line in ["commit --no-verif -m change", "push --no-verif origin main"] {
        assert!(
            check(&args(line), None).is_err(),
            "`{line}` passed the check"
        );
    }
}

/// `--receive-pack` and `--upload-pack` run a caller-chosen command for a local or
/// SSH remote, in the environment that carries `B10X_BOT_TOKEN`, as `--exec` does.
#[test]
fn receive_pack_and_upload_pack_are_refused() {
    for line in [
        "push --receive-pack=elsewhere origin main",
        "fetch --upload-pack=elsewhere origin",
    ] {
        assert!(
            check(&args(line), None).is_err(),
            "`{line}` passed the check"
        );
    }
}

/// Removing the call in `main` before `Github::bot()` must turn this red: the
/// refusal is the route, never a credential error.
#[test]
fn bot_check_runs_before_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .args(["bot", "--", "push", "--delete", "origin", "x"])
        .env_remove("B10X_GATES_POLICY")
        .env("XDG_CONFIG_HOME", &config)
        .env("B10X_BOT_CONFIG", config.join("absent-bot.json"))
        .env("B10X_BOT_KEY", config.join("absent-key.pem"))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.contains("cannot delete a remote branch"), "{stderr}");
    assert!(!stderr.contains("absent-bot.json"), "{stderr}");
}

// ---- Invariant 6: the nothing-staged diagnosis ----

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
    assert!(status.success(), "git {args:?}");
}

fn repository_with_refusing_hook() -> tempfile::TempDir {
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
    let hooks = dir.path().join(".git/hooks");
    fs::create_dir_all(&hooks).unwrap();
    let hook = hooks.join("pre-commit");
    fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    dir
}

fn refusal(result: anyhow::Result<()>) -> String {
    format!("{:#}", result.expect_err("expected a refusal"))
}

/// A pathspec without `--` commits the named file; the hook refused it, yet the
/// diagnosis says nothing is staged.
#[test]
fn nothing_staged_not_claimed_for_pathspec_commit_refused_by_hook() {
    let dir = repository_with_refusing_hook();
    fs::write(dir.path().join("readme"), "changed, named as a pathspec\n").unwrap();
    let github = Github::from_token("synthetic-token".into()).unwrap();
    let text = refusal(github.git(dir.path(), &args("commit -m change readme")));
    assert!(!text.contains("nothing staged"), "{text}");
}

/// The documented merge route: `git merge --no-ff --no-commit` of a branch whose
/// tree equals HEAD, then a commit the hook refuses.
#[test]
fn nothing_staged_not_claimed_for_merge_refused_by_hook() {
    let dir = repository_with_refusing_hook();
    let hook = dir.path().join(".git/hooks/pre-commit");
    fs::rename(&hook, dir.path().join(".git/hook.off")).unwrap();
    git(dir.path(), &["switch", "-qc", "side"]);
    fs::write(dir.path().join("extra"), "x\n").unwrap();
    git(dir.path(), &["add", "extra"]);
    git(dir.path(), &["commit", "-qm", "add"]);
    git(dir.path(), &["rm", "-q", "extra"]);
    git(dir.path(), &["commit", "-qm", "remove"]);
    git(dir.path(), &["switch", "-q", "main"]);
    git(
        dir.path(),
        &["merge", "-q", "--no-ff", "--no-commit", "side"],
    );
    fs::rename(dir.path().join(".git/hook.off"), &hook).unwrap();
    let github = Github::from_token("synthetic-token".into()).unwrap();
    let text = refusal(github.git(dir.path(), &args("commit -m merge")));
    assert!(!text.contains("nothing staged"), "{text}");
}

// ---- Invariant 2: GitHub's 4xx text is vetted before it is shown ----

fn withheld(body: &serde_json::Value) {
    let text = delivery::api_failure_for_test(422, body.to_string().as_bytes(), &matchers());
    assert!(
        text.contains("message withheld: it matches a private rule"),
        "{body}: {text}"
    );
}

#[test]
fn api_message_vetting_covers_split_and_hidden_forms() {
    let lit = literal();
    let (a, b) = lit.split_at(9);
    let s = short_literal();
    let (sa, sb) = s.split_at(2);
    let home = ["", "home", "example", ""].join("/");
    let cases = [
        json!({"message": a, "errors": [b]}),
        json!({"message": sa, "errors": [{"message": sb}]}),
        json!({"message": "ok", "errors": [{"resource": sa, "field": sb}]}),
        json!({"message": format!("{sa}\u{7}{sb}")}),
        json!({"message": format!("{sa}\u{200b}{sb}")}),
        json!({"message": format!("{a}\u{2060}{b}")}),
        json!({"message": format!("{}{lit}", "x".repeat(400))}),
        json!({"message": "ok", "errors": [{"code": lit.clone()}]}),
        json!({"message": "ok", "errors": [{"resource": home.clone()}]}),
        json!({"message": format!("see{}", "\u{7}") + &home}),
    ];
    for body in &cases {
        withheld(body);
    }
    let escaped = format!(r#"{{"message":"{sa}s{}"}}"#, &sb[1..]);
    let text = delivery::api_failure_for_test(422, escaped.as_bytes(), &matchers());
    assert!(text.contains("withheld"), "{escaped}: {text}");
}

#[test]
fn api_message_never_shows_unvetted_shapes() {
    let lit = literal();
    let mut errors: Vec<_> = (0..10).map(|i| json!(format!("entry {i}"))).collect();
    errors.push(json!(lit.clone()));
    for body in [
        json!({"message": "ok", "errors": errors}),
        json!({"message": {"nested": lit.clone()}}),
        json!({"message": "ok", "errors": [{"resource": {"nested": lit.clone()}}]}),
        json!({"message": "ok", "documentation_url": lit.clone()}),
    ] {
        let text = delivery::api_failure_for_test(422, body.to_string().as_bytes(), &matchers());
        assert!(!text.contains(&lit), "{body}: {text}");
    }
}

// ---- Invariant 3: the html_url shown after a failed response write ----

#[test]
fn html_url_is_shown_only_when_vetted() {
    let output = Path::new("response.json");
    let url = |u: &str| json!({"number": 1, "html_url": u});
    let shown = |response: serde_json::Value, matchers: Option<&Matchers>| {
        delivery::api_success_report(201, &response, output, Err(anyhow::anyhow!("x")), matchers)
            .unwrap()
            .stdout
    };
    let m = matchers();
    let private = format!("https://github.com/example/{}/pull/1", literal());
    let text = shown(url(&private), Some(&m));
    assert!(
        !text.contains(&literal()) && text.contains("URL withheld"),
        "{text}"
    );
    let plain = "https://github.com/example/example/pull/1";
    let text = shown(url(plain), None);
    assert!(
        !text.contains(plain) && text.contains("URL withheld"),
        "{text}"
    );
    let text = shown(url("https://github.com/example/\u{1b}[2Jx"), Some(&m));
    assert!(text.contains("URL withheld"), "{text}");
    let text = shown(url("http://github.com/example/example/pull/1"), Some(&m));
    assert!(text.contains("URL withheld"), "{text}");
}
