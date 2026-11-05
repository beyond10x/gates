//! Adversarial cases for `story:ci-fetch-head-by-sha`: `ci` fetches a pull request's head
//! commit by its id, falls back to `refs/pull/<n>/head`, binds the candidate to the id
//! either way, and a refused fetch names the refspec and git's message without the
//! workflow credential or private-rule text.
//!
//! A local remote answers protocol v2 by serving any object by id, so the cases that need
//! the id refused run the client on protocol v0, where an unadvertised object is refused
//! as GitHub refuses one. Such a case re-runs itself as a child test process with
//! `GIT_CONFIG_PARAMETERS` set, which every git child inherits.
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    git::Candidate,
    policy::{Policy, Repository},
};
use std::{collections::BTreeMap, path::Path, process::Command, sync::Mutex};
use tempfile::TempDir;

const REPOSITORY: &str = "example/repository";
const NUMBER: u64 = 7;
const CHILD: &str = "B10X_GATES_ADVERSARY_CI_FETCH_V0";

/// In the parent: runs the case `name` again in a child on protocol v0, asserts it
/// passed, and returns true. In the child: returns false, so the case body runs.
fn in_v0(name: &str) -> bool {
    if std::env::var_os(CHILD).is_some() {
        return false;
    }
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--test-threads=1", "--nocapture"])
        .env(CHILD, "1")
        .env("GIT_CONFIG_PARAMETERS", "'protocol.version'='0'")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("1 passed") || stdout.contains("1 failed"),
        "the child did not run {name}: {stdout}"
    );
    assert!(output.status.success(), "{name} on protocol v0: {stderr}");
    true
}

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
    assert!(
        output.status.success(),
        "Git fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

/// `base` at the baseline; the pull request commit `head` on no ref; `later`, a child of
/// `head`; `other`, a commit unrelated to `head` on top of the baseline.
struct Remote {
    dir: TempDir,
    baseline: String,
    head: String,
    later: String,
    other: String,
}

impl Remote {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(
            root,
            &[
                "-c",
                "init.templateDir=",
                "init",
                "-q",
                "--initial-branch=base",
            ],
        );
        let commit = |path: &str, bytes: &[u8]| {
            std::fs::write(root.join(path), bytes).unwrap();
            git(root, &["add", "--", path]);
            git(root, &["commit", "-qm", path]);
            git(root, &["rev-parse", "HEAD"])
        };
        let baseline = commit("readme", b"initial safe bytes\n");
        git(root, &["checkout", "-q", "-b", "feature"]);
        let head = commit("feature.txt", b"pull request bytes\n");
        let later = commit("later.txt", b"a later push\n");
        git(root, &["checkout", "-q", "-b", "other", &baseline]);
        let other = commit("other.txt", b"another history\n");
        git(root, &["checkout", "-q", "base"]);
        git(root, &["branch", "-q", "-D", "feature", "other"]);
        Self {
            dir,
            baseline,
            head,
            later,
            other,
        }
    }

    fn pull_ref(&self, at: &str) {
        git(
            self.dir.path(),
            &["update-ref", &format!("refs/pull/{NUMBER}/head"), at],
        );
    }

    fn policy(&self, literals: &[&str]) -> Policy {
        Policy {
            version: 2,
            nonce: "synthetic-policy-nonce-for-adversary-1234".into(),
            forbidden_literals: literals.iter().map(|v| (*v).to_owned()).collect(),
            forbidden_patterns: vec![],
            allow_patterns: vec![],
            repositories: BTreeMap::from([(
                REPOSITORY.into(),
                Repository {
                    id: "123".into(),
                    baseline: self.baseline.clone(),
                },
            )]),
            signers: BTreeMap::new(),
            exceptions: vec![],
        }
    }

    fn event(&self, head: &str, from: &str) -> serde_json::Value {
        serde_json::json!({
            "action": "synchronize",
            "number": NUMBER,
            "pull_request": {
                "number": NUMBER,
                "head": {"sha": head, "ref": "feature", "repo": {"full_name": from}},
                "base": {"sha": self.baseline, "ref": "base", "repo": {"full_name": REPOSITORY}}
            },
            "repository": {"id": 123, "full_name": REPOSITORY}
        })
    }

    /// Runs `ci`, returning the candidate and every repository name it asked a remote for.
    fn ci(&self, event: &serde_json::Value) -> (anyhow::Result<Candidate>, Vec<String>) {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("event.json");
        std::fs::write(&path, serde_json::to_vec(event).unwrap()).unwrap();
        let remote = self.dir.path().display().to_string();
        let asked = Mutex::new(Vec::new());
        let result = b10x_gates::delivery::ci_candidate_from(
            &self.policy(&[]),
            &path,
            &scratch.path().join("candidate.git"),
            |repository| {
                asked.lock().unwrap().push(repository.to_owned());
                remote.clone()
            },
        )
        .map(|(_, candidate)| candidate);
        (result, asked.into_inner().unwrap())
    }
}

#[test]
fn the_pull_ref_fallback_is_used_when_the_id_is_refused_and_the_id_is_bound() {
    if in_v0("the_pull_ref_fallback_is_used_when_the_id_is_refused_and_the_id_is_bound") {
        return;
    }
    let remote = Remote::new();
    remote.pull_ref(&remote.later);
    let (result, _) = remote.ci(&remote.event(&remote.head, REPOSITORY));
    let candidate = result.expect("the fallback ref carries the head commit");
    assert_eq!(candidate.binding.head, remote.head);
    assert_eq!(candidate.binding.commits, vec![remote.head.clone()]);
    let locations: Vec<_> = candidate
        .units
        .iter()
        .map(|u| u.location.as_str())
        .collect();
    assert!(!locations.contains(&"file:later.txt"), "{locations:?}");
}

#[test]
fn a_fallback_ref_without_the_head_names_the_refused_id() {
    // The id is refused and `refs/pull/<n>/head` names an unrelated commit, as after a
    // force-push when an old run is re-run: the fetch of the ref succeeds, the head is not
    // there, and `ci` must still say which fetch git refused.
    if in_v0("a_fallback_ref_without_the_head_names_the_refused_id") {
        return;
    }
    let remote = Remote::new();
    remote.pull_ref(&remote.other);
    let (result, _) = remote.ci(&remote.event(&remote.head, REPOSITORY));
    let error = result
        .err()
        .expect("the head is not in the store")
        .to_string();
    assert!(
        error.contains(&format!("git refused {}", remote.head)),
        "{error}"
    );
}

#[test]
fn a_cross_repository_head_is_fetched_from_the_base_repository_and_bound_by_id() {
    if in_v0("a_cross_repository_head_is_fetched_from_the_base_repository_and_bound_by_id") {
        return;
    }
    let remote = Remote::new();
    remote.pull_ref(&remote.head);
    let (result, asked) = remote.ci(&remote.event(&remote.head, "someone/fork"));
    let candidate = result.expect("the base repository serves the fork head");
    assert_eq!(candidate.binding.head, remote.head);
    assert_eq!(asked, vec![REPOSITORY.to_owned()]);
}

#[test]
fn an_event_head_that_is_not_a_lowercase_full_id_is_refused_before_any_fetch() {
    let remote = Remote::new();
    remote.pull_ref(&remote.head);
    let marker = remote.dir.path().join("injected");
    let option = format!("--upload-pack=touch {}", marker.display());
    let upper = remote.head.to_uppercase();
    let short = remote.head[..7].to_owned();
    let newline = format!("{}\n", remote.head);
    let ranged = format!("{}..{}", remote.baseline, remote.head);
    for head in [
        option.as_str(),
        "-",
        "--all",
        upper.as_str(),
        short.as_str(),
        newline.as_str(),
        ranged.as_str(),
        "refs/pull/7/head",
        "HEAD",
    ] {
        let (result, _) = remote.ci(&remote.event(head, REPOSITORY));
        let error = result.err().expect("a crafted head is refused").to_string();
        assert_eq!(error, "event must name an exact commit", "{head:?}");
        assert!(!marker.exists(), "{head:?} ran a command");
    }
}

#[test]
fn a_pull_request_number_that_is_not_a_number_is_refused() {
    let remote = Remote::new();
    for number in [
        serde_json::json!("7/head refs/heads/base"),
        serde_json::json!(-7),
        serde_json::json!(7.5),
    ] {
        let mut event = remote.event(&remote.head, REPOSITORY);
        event["number"] = number.clone();
        event["pull_request"]["number"] = number.clone();
        let (result, asked) = remote.ci(&event);
        let error = result.err().expect("a bad number is refused").to_string();
        assert_eq!(error, "PR number missing", "{number}");
        assert!(asked.is_empty(), "{number}");
    }
}

#[test]
fn a_push_never_falls_back_to_a_pull_ref() {
    // A push of a commit the remote refuses is not rescued by a pull request ref that
    // carries it.
    if in_v0("a_push_never_falls_back_to_a_pull_ref") {
        return;
    }
    let remote = Remote::new();
    remote.pull_ref(&remote.later);
    let push = serde_json::json!({
        "ref": "refs/heads/base",
        "after": remote.head,
        "repository": {"id": 123, "full_name": REPOSITORY}
    });
    let (result, _) = remote.ci(&push);
    let error = result
        .err()
        .expect("the push commit is refused")
        .to_string();
    assert!(
        error.contains(&format!("git refused {}", remote.head)),
        "{error}"
    );
    assert!(!error.contains("refs/pull/"), "{error}");
}

// --- what a refused fetch prints ----------------------------------------------------

const PULL: &str = "refs/pull/7/head";
const ABSENT: &str = "1111111111111111111111111111111111111111";

fn token() -> String {
    [
        "ghs",
        "_",
        "synthetic",
        "Adversary",
        "Token",
        "ForLocal0123",
    ]
    .concat()
}

fn printed(stderr: &str, literals: &[&str]) -> String {
    let remote = Remote::new();
    b10x_gates::delivery::fetch_refusal_for_test(
        stderr.as_bytes(),
        &[PULL, ABSENT],
        &remote.policy(literals),
        &token(),
    )
}

#[test]
fn a_token_split_by_a_format_character_is_withheld() {
    // The private-rule matchers drop Unicode format characters before matching; the
    // credential check removes control characters only, so a zero-width space inside
    // the token leaves its whole text on the line shown.
    let token = token();
    let stderr = format!(
        "fatal: couldn't find remote ref {PULL} {}\u{200b}{}\n",
        &token[..10],
        &token[10..]
    );
    let shown = printed(&stderr, &[]);
    assert!(!shown.contains(&token[10..]), "{shown}");
}

#[test]
fn a_private_term_split_by_a_format_or_control_character_is_withheld() {
    let term = ["synthetic", "restricted", "identifier"].join("-");
    let (left, right) = term.split_at(9);
    for joint in ["\u{200b}", "\u{ad}", "\r", "\u{7}", "\n"] {
        let stderr = format!("fatal: couldn't find remote ref {PULL} {left}{joint}{right}\n");
        let shown = printed(&stderr, &[&term]);
        assert!(!shown.contains(right), "{joint:?}: {shown}");
        assert!(
            shown.starts_with(&format!("git refused {PULL}: ")),
            "{shown}"
        );
    }
}

#[test]
fn a_private_term_cut_by_the_message_limit_is_withheld() {
    let term = ["synthetic", "restricted", "identifier"].join("-");
    let pad = "x".repeat(300 - "fatal: ".len() - 9);
    let stderr = format!("fatal: {pad}{term} {PULL}\n");
    let shown = printed(&stderr, &[&term]);
    assert!(!shown.contains(&term[..9]), "{shown}");
    assert!(shown.contains("withheld"), "{shown}");
}

#[test]
fn a_personal_path_in_git_s_message_is_withheld() {
    let path = ["", "home", "someone", "work", "candidate.git"].join("/");
    let stderr = format!("fatal: could not write {path} for {PULL}\n");
    let shown = printed(&stderr, &[]);
    assert!(!shown.contains(&path), "{shown}");
    assert!(shown.contains("withheld"), "{shown}");
}
