//! `b10x-gates ci` reads the private policy from `B10X_GATES_POLICY_GZ` (gzip, then
//! standard base64) when it is set and non-empty, else from `B10X_GATES_POLICY_JSON`,
//! else from the protected file (modelled as `gates.delivery.LoadCiPolicy` in
//! `ess/domains/delivery.yaml`). Each test is named after the outcome it holds.
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    git::Candidate,
    policy::{self, CiPolicySource, Policy, Repository},
};
use base64::Engine;
use flate2::{Compression, write::GzEncoder};
use std::{collections::BTreeMap, io::Write, path::Path, process::Command};
use tempfile::TempDir;

fn policy_json() -> String {
    let policy = Policy {
        version: 2,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::new(),
        signers: BTreeMap::new(),
        exceptions: vec![],
    };
    serde_json::to_string_pretty(&policy).unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn digest(policy: &Policy) -> serde_json::Value {
    serde_json::to_value(policy).unwrap()
}

fn refusal(compressed: Option<&str>, json: Option<&str>) -> String {
    let error = policy::ci_policy(compressed, json)
        .err()
        .expect("the policy was admitted");
    format!("{error:#}")
}

#[test]
fn loaded_from_compressed() {
    let json = policy_json();
    let compressed = encode(&gzip(json.as_bytes()));
    let (policy, source) = policy::ci_policy(Some(&compressed), None).unwrap().unwrap();
    assert_eq!(source, CiPolicySource::Compressed);
    assert_eq!(
        digest(&policy),
        digest(&Policy::parse(json.as_bytes()).unwrap())
    );
}

#[test]
fn compressed_wins_over_json() {
    let compressed = encode(&gzip(policy_json().as_bytes()));
    let (_, source) = policy::ci_policy(Some(&compressed), Some("not a policy"))
        .unwrap()
        .unwrap();
    assert_eq!(source, CiPolicySource::Compressed);
}

#[test]
fn compressed_wrapped_lines_accepted() {
    // `base64` without `-w0` wraps at 76 columns; the line breaks are not data.
    let compressed = encode(&gzip(policy_json().as_bytes()));
    let wrapped: Vec<String> = compressed
        .as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect();
    let wrapped = format!("{}\n", wrapped.join("\n"));
    let (_, source) = policy::ci_policy(Some(&wrapped), None).unwrap().unwrap();
    assert_eq!(source, CiPolicySource::Compressed);
}

#[test]
fn compressed_undecodable_names_the_variable() {
    let error = refusal(Some("%%% not base64 %%%"), None);
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn compressed_not_gzip_names_the_variable() {
    let error = refusal(Some(&encode(policy_json().as_bytes())), None);
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn compressed_not_a_policy_names_the_variable() {
    let error = refusal(Some(&encode(&gzip(b"{\"version\": 2}"))), None);
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn compressed_over_the_bound_names_the_variable() {
    // A valid policy padded past the bound with JSON whitespace: only the bound refuses it.
    let padded = format!("{}{}", policy_json(), " ".repeat(5 << 20));
    let error = refusal(Some(&encode(&gzip(padded.as_bytes()))), None);
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn compressed_undecodable_never_falls_back() {
    // A valid JSON policy beside a broken compressed one is not used.
    let json = policy_json();
    let error = refusal(Some("garbage"), Some(&json));
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn empty_compressed_reads_json() {
    let json = policy_json();
    let (_, source) = policy::ci_policy(Some(""), Some(&json)).unwrap().unwrap();
    assert_eq!(source, CiPolicySource::Json);
}

#[test]
fn json_path_unchanged() {
    let json = policy_json();
    let (policy, source) = policy::ci_policy(None, Some(&json)).unwrap().unwrap();
    assert_eq!(source, CiPolicySource::Json);
    assert_eq!(
        digest(&policy),
        digest(&Policy::parse(json.as_bytes()).unwrap())
    );
    // A set but empty JSON variable is still parsed, and refused, as before.
    assert_eq!(refusal(None, Some("")), "policy format invalid");
}

#[test]
fn neither_reads_the_file() {
    assert!(policy::ci_policy(None, None).unwrap().is_none());
    assert!(policy::ci_policy(Some(""), None).unwrap().is_none());
}

#[test]
fn ci_refuses_undecodable_compressed_policy() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .args(["ci", "--event", "/nonexistent/event.json", "--objects"])
        .arg(home.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("B10X_GATES_POLICY_GZ", "garbage")
        .env("B10X_GATES_POLICY_JSON", policy_json())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("B10X_GATES_POLICY_GZ"), "{stderr}");
}

#[test]
fn ci_reads_compressed_policy_before_the_event() {
    // A valid compressed policy beside a broken JSON one: `ci` gets past the policy and
    // stops at the missing event file.
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .args(["ci", "--event", "/nonexistent/event.json", "--objects"])
        .arg(home.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env(
            "B10X_GATES_POLICY_GZ",
            encode(&gzip(policy_json().as_bytes())),
        )
        .env("B10X_GATES_POLICY_JSON", "not a policy")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("policy"), "{stderr}");
}

// --- `ci` fetches a pull request's head commit by its id ---------------------------
//
// `story:ci-fetch-head-by-sha`: GitHub did not advertise `refs/pull/<n>/head` for one
// pull request while it served the head commit by id, and `ci` failed naming nothing.

const REPOSITORY: &str = "example/repository";
const NUMBER: u64 = 7;

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

/// A local repository standing in for GitHub: `main` at the baseline and the pull
/// request's commit on `feature`, and no `refs/pull/<n>/head`.
struct Remote {
    dir: TempDir,
    baseline: String,
    head: String,
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
        git(root, &["checkout", "-q", "main"]);
        Self {
            dir,
            baseline,
            head,
        }
    }

    fn policy(&self, baseline: &str, literals: &[&str]) -> Policy {
        Policy {
            version: 2,
            nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
            forbidden_literals: literals.iter().map(|v| (*v).to_owned()).collect(),
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

    /// A `pull_request_target` payload for pull request `NUMBER` at `head`.
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

    fn ci(&self, policy: &Policy, event: &serde_json::Value) -> anyhow::Result<Candidate> {
        let scratch = tempfile::tempdir().unwrap();
        let path = scratch.path().join("event.json");
        std::fs::write(&path, serde_json::to_vec(event).unwrap()).unwrap();
        let remote = self.dir.path().display().to_string();
        b10x_gates::delivery::ci_candidate_from(
            policy,
            &path,
            &scratch.path().join("candidate.git"),
            |_| remote.clone(),
        )
        .map(|(_, candidate)| candidate)
    }

    fn refusal(&self, policy: &Policy, event: &serde_json::Value) -> String {
        // `main` prints the top-level message only, so that is what is asserted.
        let error = self.ci(policy, event).err().expect("the fetch succeeded");
        error.to_string()
    }
}

const ABSENT: &str = "1111111111111111111111111111111111111111";

#[test]
fn ci_fetches_an_unadvertised_pull_request_head_by_id_and_scans_it() {
    let remote = Remote::new();
    let advertised = git(remote.dir.path(), &["ls-remote", "."]);
    assert!(!advertised.contains("refs/pull/"), "{advertised}");
    let candidate = remote
        .ci(
            &remote.policy(&remote.baseline, &[]),
            &remote.event(&remote.head),
        )
        .expect("the head commit is served by id");
    assert_eq!(candidate.binding.head, remote.head);
    assert_eq!(candidate.binding.baseline, remote.baseline);
    assert_eq!(candidate.binding.commits, vec![remote.head.clone()]);
    let locations: Vec<_> = candidate
        .units
        .iter()
        .map(|u| u.location.as_str())
        .collect();
    assert!(locations.contains(&"file:feature.txt"), "{locations:?}");
}

#[test]
fn ci_binds_the_event_head_when_the_pull_ref_points_elsewhere() {
    // `refs/pull/<n>/head` naming another commit decides nothing: the id is the candidate.
    let remote = Remote::new();
    git(
        remote.dir.path(),
        &[
            "update-ref",
            &format!("refs/pull/{NUMBER}/head"),
            &remote.baseline,
        ],
    );
    let candidate = remote
        .ci(
            &remote.policy(&remote.baseline, &[]),
            &remote.event(&remote.head),
        )
        .expect("the head commit is served by id");
    assert_eq!(candidate.binding.head, remote.head);
}

#[test]
fn a_refused_fetch_names_each_refspec_and_git_s_message() {
    let remote = Remote::new();
    let error = remote.refusal(&remote.policy(&remote.baseline, &[]), &remote.event(ABSENT));
    assert!(
        error.starts_with("candidate object fetch failed"),
        "{error}"
    );
    // The head by id first, then the pull request ref as the fallback.
    assert!(
        error.contains(&format!("git refused {ABSENT}: ")),
        "{error}"
    );
    assert!(error.contains(&format!("not our ref {ABSENT}")), "{error}");
    let pull = format!("refs/pull/{NUMBER}/head");
    assert!(error.contains(&format!("git refused {pull}: ")), "{error}");
    assert!(
        error.contains(&format!("couldn't find remote ref {pull}")),
        "{error}"
    );
    assert!(!error.contains(&remote.baseline), "{error}");
}

#[test]
fn a_refused_baseline_is_named_with_git_s_message() {
    let remote = Remote::new();
    let error = remote.refusal(&remote.policy(ABSENT, &[]), &remote.event(&remote.head));
    assert!(
        error.starts_with("candidate object fetch failed"),
        "{error}"
    );
    assert!(
        error.contains(&format!("git refused {ABSENT}: ")),
        "{error}"
    );
    assert!(error.contains(&format!("not our ref {ABSENT}")), "{error}");
    assert!(
        !error.contains(&format!("git refused {}", remote.head)),
        "{error}"
    );
}

#[test]
fn a_refused_push_names_the_commit_git_refused() {
    let remote = Remote::new();
    let push = serde_json::json!({
        "ref": "refs/heads/main",
        "after": ABSENT,
        "repository": {"id": 123, "full_name": REPOSITORY}
    });
    let error = remote.refusal(&remote.policy(&remote.baseline, &[]), &push);
    assert!(
        error.contains(&format!("git refused {ABSENT}: ")),
        "{error}"
    );
    assert!(!error.contains("refs/pull/"), "{error}");
}

#[test]
fn git_s_message_matching_a_private_rule_is_withheld_and_the_refspec_still_named() {
    let remote = Remote::new();
    // Built at run time: the term occurs in every refusal git prints for these fetches.
    let term = ["re", "mote"].concat();
    let error = remote.refusal(
        &remote.policy(&remote.baseline, &[&term]),
        &remote.event(ABSENT),
    );
    assert!(!error.contains(&term), "{error}");
    assert!(
        error.contains(&format!("git refused {ABSENT}: ")),
        "{error}"
    );
    assert!(
        error.contains(&format!("git refused refs/pull/{NUMBER}/head: ")),
        "{error}"
    );
    assert!(error.contains("withheld"), "{error}");
}

// --- what a refused fetch prints ----------------------------------------------------

fn printed(stderr: &[u8], refspecs: &[&str], literals: &[&str], token: &str) -> String {
    let policy = Remote::new().policy(ABSENT, literals);
    b10x_gates::delivery::fetch_refusal_for_test(stderr, refspecs, &policy, token)
}

const PULL: &str = "refs/pull/7/head";
/// A workflow token in GitHub's shape, built at run time so the source carries no
/// literal a secret scanner would hold.
fn token() -> String {
    [
        "ghs",
        "_",
        "synthetic",
        "Workflow",
        "Token",
        "ForLocalTest0123",
    ]
    .concat()
}

#[test]
fn a_refusal_carrying_the_workflow_token_is_withheld() {
    let token = token();
    let basic = base64::engine::general_purpose::STANDARD
        .encode(format!("x-access-token:{token}").as_bytes());
    for stderr in [
        format!("fatal: couldn't find remote ref {PULL}\nfatal: token {token} refused\n"),
        format!("fatal: couldn't find remote ref {PULL} with {token}\n"),
        format!("fatal: couldn't find remote ref {PULL} basic {basic}\n"),
        // A control character inside the value is removed from what is shown, so it
        // must not hide the value from the check.
        format!(
            "fatal: couldn't find remote ref {PULL} {}\u{7}{}\n",
            &token[..10],
            &token[10..]
        ),
    ] {
        let shown = printed(stderr.as_bytes(), &[PULL, ABSENT], &[], &token);
        assert!(!shown.contains(&token[10..]), "{shown}");
        assert!(!shown.contains(&basic), "{shown}");
        assert!(shown.contains("withheld"), "{shown}");
        assert!(
            shown.starts_with(&format!("git refused {PULL}: ")),
            "{shown}"
        );
    }
}

#[test]
fn a_private_term_on_an_earlier_line_withholds_the_line_shown() {
    let term = ["synthetic", "restricted", "identifier"].join("-");
    let stderr = format!("hint: {term}\nfatal: couldn't find remote ref {PULL}\n");
    let shown = printed(stderr.as_bytes(), &[PULL, ABSENT], &[&term], &token());
    assert_eq!(
        shown,
        format!("git refused {PULL}: git's message withheld: it matches a private rule")
    );
}

#[test]
fn a_clean_refusal_shows_git_s_last_line() {
    let stderr = format!("fatal: couldn't find remote ref {PULL}\n");
    let shown = printed(stderr.as_bytes(), &[PULL, ABSENT], &[], &token());
    assert_eq!(
        shown,
        format!("git refused {PULL}: fatal: couldn't find remote ref {PULL}")
    );
}

#[test]
fn a_refusal_naming_no_refspec_names_the_fetch() {
    let shown = printed(b"fatal: early EOF\n", &[PULL, ABSENT], &[], &token());
    assert_eq!(
        shown,
        format!("git fetch of {PULL}, {ABSENT} failed: fatal: early EOF")
    );
}

#[test]
fn a_refspec_breaking_a_private_rule_is_not_named() {
    let term = ["synthetic", "restricted", "identifier"].join("-");
    let tag = format!("refs/tags/{term}");
    let stderr = format!("fatal: couldn't find remote ref {tag}\n");
    let shown = printed(
        stderr.as_bytes(),
        &[&format!("{tag}:{tag}"), ABSENT],
        &[&term],
        &token(),
    );
    assert!(!shown.contains(&term), "{shown}");
    assert!(
        shown.starts_with("git refused a refspec (withheld): "),
        "{shown}"
    );
}
