//! Adversary cases for the published-merge review follow-ups: a refused read's text, its
//! chain, its withheld body and the 5xx fallback seen through what a reader wraps around it.
use anyhow::{Context, Result};
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    delivery::{ApiFailure, is_server_error},
    git::Git,
    policy::{Policy, Repository},
    published_merge::AuthenticatedRead,
};
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
use tempfile::TempDir;

const REPOSITORY: &str = "example/repository";
const ROOT: &str = "/repos/example/repository";
const AUTHORITY: &str = "/repos/example/repository/rulesets/7";
const REF: &str = "/repos/example/repository/git/ref/heads/main";
const SUBJECT: &str = "Merge pull request #5 from example/topic";
const PULL: &str = "/repos/example/repository/pulls/5";

type Failure = fn() -> anyhow::Error;

/// GitHub's answers by path; a path in `failures` fails with the error its function builds.
#[derive(Default)]
struct Reader {
    responses: BTreeMap<String, Value>,
    failures: BTreeMap<String, Failure>,
    calls: RefCell<Vec<String>>,
}

impl AuthenticatedRead for Reader {
    fn get(&self, path: &str) -> Result<Value> {
        self.calls.borrow_mut().push(path.to_owned());
        if let Some(failure) = self.failures.get(path) {
            return Err(failure());
        }
        self.responses
            .get(path)
            .cloned()
            .context("fixture API unavailable")
    }
}

fn git(root: &Path, args: &[&str], input: &[u8]) -> String {
    let mut child = Command::new("git")
        .args(["--no-replace-objects", "-c", "core.hooksPath=/dev/null"])
        .args(args)
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn commit(root: &Path, tree: &str, parents: &[&str], github: bool, message: &str) -> String {
    let committer = if github {
        "GitHub <noreply@github.com>".to_owned()
    } else {
        format!("{BOT_NAME} <{BOT_EMAIL}>")
    };
    let mut raw = format!("tree {tree}\n");
    for parent in parents {
        raw.push_str(&format!("parent {parent}\n"));
    }
    raw.push_str(&format!("author {BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000\ncommitter {committer} 1700000000 +0000\n\n{message}\n"));
    git(
        root,
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        raw.as_bytes(),
    )
}

/// A merge whose subject names pull request #5, proved by it, with every other read answered.
struct Fixture {
    dir: TempDir,
    merge: String,
    candidate: String,
    policy: Policy,
    api: Reader,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        git(
            dir.path(),
            &["init", "-q", "--initial-branch=main", "--template="],
            b"",
        );
        let tree = git(dir.path(), &["mktree"], b"");
        let baseline = commit(dir.path(), &tree, &[], false, "baseline");
        let topic = commit(dir.path(), &tree, &[&baseline], false, "topic");
        let merge = commit(dir.path(), &tree, &[&baseline, &topic], true, SUBJECT);
        let candidate = commit(dir.path(), &tree, &[&merge], false, "candidate");
        git(
            dir.path(),
            &["update-ref", "refs/heads/main", &candidate],
            b"",
        );
        let policy = Policy {
            version: 1,
            nonce: "synthetic-authority-test-policy".into(),
            forbidden_literals: vec![],
            forbidden_patterns: vec![],
            allow_patterns: vec![],
            repositories: BTreeMap::from([(
                REPOSITORY.into(),
                Repository {
                    id: "123".into(),
                    baseline: baseline.clone(),
                },
            )]),
            signers: BTreeMap::new(),
            exceptions: vec![],
        };
        let mut api = Reader::default();
        api.responses.insert(ROOT.into(), json!({"id":123,"full_name":REPOSITORY,"private":false,"visibility":"public","default_branch":"main"}));
        api.responses.insert(
            format!("{ROOT}/rulesets?includes_parents=true&per_page=100&page=1"),
            json!([{"id":7,"name":"b10x-bot-branch-authority"}]),
        );
        api.responses.insert(AUTHORITY.into(), json!({"id":7,"name":"b10x-bot-branch-authority","target":"branch","enforcement":"active","bypass_actors":[{"actor_id":4579525,"actor_type":"Integration","bypass_mode":"always"}],"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},"rules":[{"type":"creation"},{"type":"update"},{"type":"deletion"},{"type":"non_fast_forward"}]}));
        api.responses.insert(
            REF.into(),
            json!({"ref":"refs/heads/main","object":{"type":"commit","sha":merge}}),
        );
        api.responses.insert(format!("{ROOT}/commits/{merge}"), json!({
            "sha":merge,"author":{"login":BOT_NAME},"committer":{"login":"web-flow"},
            "commit":{"author":{"name":BOT_NAME,"email":BOT_EMAIL},"committer":{"name":"GitHub","email":"noreply@github.com"},"tree":{"sha":tree},"verification":{"verified":true,"reason":"valid"}},
            "parents":[{"sha":baseline},{"sha":topic}]
        }));
        let pr = json!({"number":5,"state":"closed","merged":true,"merge_commit_sha":merge,"merged_by":{"login":BOT_NAME},"head":{"sha":topic,"repo":{"full_name":REPOSITORY,"id":123}},"base":{"ref":"main","repo":{"full_name":REPOSITORY,"id":123}}});
        api.responses.insert(list(&merge), json!([pr.clone()]));
        api.responses.insert(PULL.into(), pr);
        Self {
            dir,
            merge,
            candidate,
            policy,
            api,
        }
    }

    fn fail(&mut self, path: &str, failure: Failure) {
        self.api.responses.remove(path);
        self.api.failures.insert(path.to_owned(), failure);
    }

    fn verify(&self) -> Result<()> {
        let git = Git::new(self.dir.path())?;
        b10x_gates::delivery::verify_publication(
            &git,
            &self.policy,
            REPOSITORY,
            &self.candidate,
            &self.api,
        )
    }

    fn read(&self, path: &str) -> bool {
        self.api.calls.borrow().iter().any(|call| call == path)
    }
}

fn list(merge: &str) -> String {
    format!("{ROOT}/commits/{merge}/pulls?per_page=100&page=1")
}

fn texts(error: &anyhow::Error) -> [String; 3] {
    [
        format!("{error}"),
        format!("{error:#}"),
        format!("{error:?}"),
    ]
}

#[test]
fn the_fixture_admits_before_anything_fails() {
    let f = Fixture::new();
    f.verify().expect("the unbroken fixture must admit");
    assert!(f.read(&list(&f.merge)));
}

/// `is_server_error` promises a 5xx "under any context"; a refused read is such an error.
#[test]
fn a_refused_read_is_still_a_server_error_to_its_public_predicate() {
    let mut f = Fixture::new();
    f.fail(AUTHORITY, || {
        ApiFailure::new(StatusCode::SERVICE_UNAVAILABLE, None).into()
    });
    let error = f.verify().expect_err("a failing authority admitted");
    assert!(format!("{error}").contains("503"), "{error:#}");
    assert!(
        is_server_error(&error),
        "a 503 refusal is no longer a server error: {error:#}"
    );
    assert_eq!(
        error.downcast_ref::<ApiFailure>().map(ApiFailure::status),
        Some(StatusCode::SERVICE_UNAVAILABLE),
        "{error:#}"
    );
}

/// A reader that adds its own context around GitHub's 5xx still falls back.
#[test]
fn a_server_error_under_the_reader_s_own_context_still_falls_back() {
    let mut f = Fixture::new();
    let path = list(&f.merge);
    f.fail(&path, || {
        anyhow::Error::from(ApiFailure::new(StatusCode::BAD_GATEWAY, None))
            .context("inner layer")
            .context("outer layer")
    });
    f.verify().expect("a wrapped 502 must fall back");
    assert!(f.read(PULL), "the named pull request was not read");
}

/// A 429 or a transport failure on the list is not a 5xx and never falls back, wrapped or not.
#[test]
fn a_non_server_failure_on_the_list_never_falls_back() {
    let failures: [Failure; 3] = [
        || ApiFailure::new(StatusCode::TOO_MANY_REQUESTS, None).into(),
        || {
            anyhow::Error::from(ApiFailure::new(StatusCode::TOO_MANY_REQUESTS, None))
                .context("rate limited")
        },
        || anyhow::anyhow!("GitHub request failed; sensitive response withheld"),
    ];
    for failure in failures {
        let mut f = Fixture::new();
        let path = list(&f.merge);
        f.fail(&path, failure);
        let error = f.verify().expect_err("a non-5xx list admitted");
        assert!(!f.read(PULL), "fell back on {error:#}");
        let read = format!("GET {path}: ");
        for text in texts(&error) {
            assert_eq!(text.matches(&read).count(), 1, "{text}");
        }
    }
}

/// Every context layer a reader adds below the status stays in the chain once.
#[test]
fn a_refused_read_keeps_each_layer_and_its_status_once() {
    let mut f = Fixture::new();
    f.fail(AUTHORITY, || {
        anyhow::Error::from(ApiFailure::new(StatusCode::NOT_FOUND, None))
            .context("layer one")
            .context("layer two")
    });
    let error = f.verify().expect_err("a failing authority admitted");
    let read = format!("GET {AUTHORITY}: ");
    assert_eq!(format!("{error}"), format!("{read}layer two"));
    let [_, full, debug] = texts(&error);
    for text in [full, debug] {
        for part in [
            read.as_str(),
            "layer two",
            "layer one",
            &StatusCode::NOT_FOUND.to_string(),
        ] {
            assert_eq!(text.matches(part).count(), 1, "{part}: {text}");
        }
    }
}

const BODY: &str = "withheld-body-marker";

fn with_body(status: StatusCode) -> anyhow::Error {
    ApiFailure::new(
        status,
        Some(json!({"message": BODY, "errors": [BODY, {"resource": BODY, "message": BODY}]})),
    )
    .into()
}

/// GitHub's body never reaches any form of a refused read, direct or through the fallback.
#[test]
fn a_refused_read_withholds_the_response_body() {
    let mut f = Fixture::new();
    f.fail(AUTHORITY, || with_body(StatusCode::FORBIDDEN));
    let direct = f.verify().expect_err("a forbidden authority admitted");

    let mut f = Fixture::new();
    let path = list(&f.merge);
    f.fail(&path, || with_body(StatusCode::INTERNAL_SERVER_ERROR));
    f.fail(PULL, || with_body(StatusCode::UNPROCESSABLE_ENTITY));
    let fallback = f.verify().expect_err("both reads failing admitted");

    for error in [direct, fallback] {
        for text in texts(&error) {
            assert!(text.contains("GET "), "{text}");
            assert!(!text.contains(BODY), "body shown: {text}");
        }
    }
}

/// When the fallback's own read is refused, that read keeps its deeper cause once, as a
/// direct refusal does.
#[test]
fn the_fallback_s_refused_read_keeps_its_deeper_cause() {
    let mut f = Fixture::new();
    let path = list(&f.merge);
    f.fail(&path, || {
        ApiFailure::new(StatusCode::INTERNAL_SERVER_ERROR, None).into()
    });
    f.fail(PULL, || {
        anyhow::anyhow!("deeper cause marker").context("top cause marker")
    });
    let error = f
        .verify()
        .expect_err("a failing named pull request admitted");
    let [_, full, debug] = texts(&error);
    for text in [full, debug] {
        for part in [
            format!("GET {PULL}: "),
            "top cause marker".into(),
            "deeper cause marker".into(),
        ] {
            assert_eq!(text.matches(&part).count(), 1, "{part}: {text}");
        }
    }
}
