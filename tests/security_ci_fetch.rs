//! Security review of `story:ci-fetch-head-by-sha`: conformance cases for the contract the
//! unit states in `README.md` (the candidate is the pull request's head id, whichever fetch
//! brought it) and for what a refused fetch may print (never the workflow credential, and
//! nothing at all when the trusted matchers are unavailable).
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    git::Candidate,
    policy::{Policy, Repository},
};
use std::{collections::BTreeMap, path::Path, process::Command};
use tempfile::TempDir;

const REPOSITORY: &str = "example/repository";
const NUMBER: u64 = 7;
const PULL: &str = "refs/pull/7/head";
const ABSENT: &str = "1111111111111111111111111111111111111111";

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

fn policy(baseline: &str, patterns: &[&str]) -> Policy {
    Policy {
        version: 2,
        nonce: "synthetic-policy-nonce-for-security-review-1234".into(),
        forbidden_literals: vec![],
        forbidden_patterns: patterns.iter().map(|v| (*v).to_owned()).collect(),
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

/// A local repository standing in for GitHub: `main` at the baseline, the pull request's
/// commit on `feature`, and an annotated tag object pointing at that commit.
struct Remote {
    dir: TempDir,
    baseline: String,
    head: String,
    tag: String,
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
                "--initial-branch=main",
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
        git(root, &["tag", "-a", "-m", "annotated", "annotated", &head]);
        let tag = git(root, &["rev-parse", "refs/tags/annotated"]);
        git(root, &["checkout", "-q", "main"]);
        Self {
            dir,
            baseline,
            head,
            tag,
        }
    }

    fn event(&self, head: &str) -> serde_json::Value {
        serde_json::json!({
            "action": "synchronize",
            "number": NUMBER,
            "pull_request": {
                "number": NUMBER,
                "head": {"sha": head, "ref": "feature", "repo": {"full_name": REPOSITORY}},
                "base": {"sha": self.baseline, "ref": "main", "repo": {"full_name": REPOSITORY}}
            },
            "repository": {"id": 123, "full_name": REPOSITORY}
        })
    }

    fn ci(&self, event: &serde_json::Value) -> anyhow::Result<Candidate> {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("event.json");
        std::fs::write(&path, serde_json::to_vec(event).unwrap()).unwrap();
        let remote = self.dir.path().display().to_string();
        b10x_gates::delivery::ci_candidate_from(
            &policy(&self.baseline, &[]),
            &path,
            &scratch.path().join("candidate.git"),
            |_| remote.clone(),
        )
        .map(|(_, candidate)| candidate)
    }
}

/// A workflow token in GitHub's shape, built at run time so the source carries no literal
/// a secret scanner would hold.
fn token() -> String {
    [
        "ghs",
        "_",
        "synthetic",
        "Review",
        "Token",
        "ForLocalTest0123",
    ]
    .concat()
}

#[test]
fn a_pull_request_head_naming_a_tag_object_binds_no_other_commit() {
    // README: "the candidate is the id either way". An id that names a tag object is not a
    // commit; peeling it binds the candidate to a commit the event did not name.
    let remote = Remote::new();
    assert_ne!(remote.tag, remote.head);
    assert_eq!(
        git(remote.dir.path(), &["cat-file", "-t", &remote.tag]),
        "tag"
    );
    match remote.ci(&remote.event(&remote.tag)) {
        Err(_) => {}
        Ok(candidate) => assert_eq!(
            candidate.binding.head, remote.tag,
            "the event named tag object {} and the candidate is commit {}",
            remote.tag, candidate.binding.head
        ),
    }
}

#[test]
fn a_token_split_by_an_invalid_byte_is_withheld() {
    // Lossy decoding turns an invalid byte into U+FFFD, which is neither a control nor a
    // format character, so neither the credential check nor a format-character strip
    // rejoins the token; the line shown then carries all of it but one byte.
    let token = token();
    let mut stderr = format!("fatal: couldn't find remote ref {PULL} ").into_bytes();
    stderr.extend_from_slice(&token.as_bytes()[..10]);
    stderr.push(0xff);
    stderr.extend_from_slice(&token.as_bytes()[10..]);
    stderr.push(b'\n');
    let shown = b10x_gates::delivery::fetch_refusal_for_test(
        &stderr,
        &[PULL, ABSENT],
        &policy(ABSENT, &[]),
        &token,
    );
    assert!(!shown.contains(&token[10..]), "{shown}");
    assert!(shown.contains("withheld"), "{shown}");
}

#[test]
fn without_trusted_matchers_no_refspec_and_no_message_is_shown() {
    // A policy whose matchers do not build leaves nothing to decide what is private:
    // both the refspec and git's line are withheld, the refusal is still a refusal.
    let line = format!("fatal: couldn't find remote ref {PULL}");
    let shown = b10x_gates::delivery::fetch_refusal_for_test(
        format!("{line}\n").as_bytes(),
        &[PULL, ABSENT],
        &policy(ABSENT, &[".*"]),
        &token(),
    );
    assert!(!shown.contains(PULL), "{shown}");
    assert!(!shown.contains(&line), "{shown}");
    assert_eq!(
        shown,
        "git refused a refspec (withheld): git's message withheld: trusted policy unavailable"
    );
}
