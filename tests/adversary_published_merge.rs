use anyhow::{Context, Result};
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    git::Git,
    policy::{Policy, Repository},
    published_merge::AuthenticatedRead,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
use tempfile::TempDir;

const REPOSITORY: &str = "example/review";
const ROOT: &str = "/repos/example/review";
const RULES: &str = "/repos/example/review/rulesets?includes_parents=true&per_page=100&page=1";
const REF: &str = "/repos/example/review/git/ref/heads/main";

struct Evidence(BTreeMap<String, Value>);

impl AuthenticatedRead for Evidence {
    fn get(&self, path: &str) -> Result<Value> {
        self.0
            .get(path)
            .cloned()
            .context("missing synthetic response")
    }
}

fn git(root: &Path, args: &[&str], bytes: &[u8]) -> String {
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
    child.stdin.take().unwrap().write_all(bytes).unwrap();
    let result = child.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap().trim().to_owned()
}

fn commit(root: &Path, tree: &str, parents: &[&str], committer: &str, message: &str) -> String {
    let mut raw = format!("tree {tree}\n");
    for parent in parents {
        raw.push_str(&format!("parent {parent}\n"));
    }
    raw.push_str(&format!(
        "author {BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000\ncommitter {committer} 1700000000 +0000\n\n{message}\n"
    ));
    git(
        root,
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        raw.as_bytes(),
    )
}

struct Fixture {
    directory: TempDir,
    tree: String,
    baseline: String,
    topic: String,
    merge: String,
    candidate: String,
    evidence: Evidence,
    policy: Policy,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        git(
            directory.path(),
            &["init", "-q", "--initial-branch=main", "--template="],
            b"",
        );
        let tree = git(directory.path(), &["mktree"], b"");
        let bot = format!("{BOT_NAME} <{BOT_EMAIL}>");
        let baseline = commit(directory.path(), &tree, &[], &bot, "baseline");
        let topic = commit(directory.path(), &tree, &[&baseline], &bot, "topic");
        let merge = commit(
            directory.path(),
            &tree,
            &[&baseline, &topic],
            "GitHub <noreply@github.com>",
            "published",
        );
        let candidate = commit(directory.path(), &tree, &[&merge], &bot, "candidate");
        let evidence = Evidence(BTreeMap::from([
            (
                ROOT.into(),
                json!({"id":123,"full_name":REPOSITORY,"private":false,"visibility":"public","default_branch":"main"}),
            ),
            (
                RULES.into(),
                json!([{"id":7,"name":"b10x-bot-branch-authority"}]),
            ),
            (
                format!("{ROOT}/rulesets/7"),
                json!({"id":7,"name":"b10x-bot-branch-authority","target":"branch","enforcement":"active","bypass_actors":[{"actor_id":4579525,"actor_type":"Integration","bypass_mode":"always"}],"conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},"rules":[{"type":"creation"},{"type":"update"},{"type":"deletion"},{"type":"non_fast_forward"}]}),
            ),
            (
                REF.into(),
                json!({"ref":"refs/heads/main","object":{"type":"commit","sha":merge}}),
            ),
        ]));
        let policy = Policy {
            version: 1,
            nonce: "synthetic-adversary-policy".into(),
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
        let mut fixture = Self {
            directory,
            tree,
            baseline,
            topic,
            merge,
            candidate,
            evidence,
            policy,
        };
        fixture.prove(
            fixture.merge.clone(),
            fixture.baseline.clone(),
            fixture.topic.clone(),
            1,
        );
        fixture
    }

    fn prove(&mut self, merge: String, first: String, second: String, number: u64) {
        self.evidence.0.insert(
            format!("{ROOT}/commits/{merge}"),
            json!({
                "sha":merge,
                "author":{"login":BOT_NAME},"committer":{"login":"web-flow"},
                "commit":{"author":{"name":BOT_NAME,"email":BOT_EMAIL},
                    "committer":{"name":"GitHub","email":"noreply@github.com"},
                    "tree":{"sha":self.tree},"verification":{"verified":true,"reason":"valid"}},
                "parents":[{"sha":first},{"sha":second}]
            }),
        );
        let pr = json!({"number":number,"merged":true,"state":"closed","merge_commit_sha":merge,
            "merged_by":{"login":BOT_NAME},
            "head":{"sha":second,"repo":{"id":123,"full_name":REPOSITORY}},
            "base":{"ref":"main","repo":{"id":123,"full_name":REPOSITORY}}});
        self.evidence.0.insert(
            format!("{ROOT}/commits/{merge}/pulls?per_page=100&page=1"),
            json!([pr.clone()]),
        );
        self.evidence.0.insert(format!("{ROOT}/pulls/{number}"), pr);
    }

    fn verify(&self) -> [Result<()>; 2] {
        let git = Git::new(self.directory.path()).unwrap();
        [
            b10x_gates::delivery::verify_publication(
                &git,
                &self.policy,
                REPOSITORY,
                &self.candidate,
                &self.evidence,
            ),
            b10x_gates::hooks::verify_pre_push(
                &git,
                &self.policy,
                REPOSITORY,
                &self.candidate,
                &self.evidence,
            ),
        ]
    }

    fn assert_valid(&self) {
        for result in self.verify() {
            assert!(result.is_ok(), "valid control refused: {result:?}");
        }
    }
}

#[test]
fn adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists() {
    let mut accepted = Vec::new();
    for rules in [true, false] {
        for malformed in [Value::Null, json!({}), json!({"id":8,"number":2})] {
            let mut fixture = Fixture::new();
            fixture.assert_valid();
            let path = if rules {
                RULES.to_owned()
            } else {
                format!("{ROOT}/commits/{}/pulls?per_page=100&page=1", fixture.merge)
            };
            fixture
                .evidence
                .0
                .get_mut(&path)
                .unwrap()
                .as_array_mut()
                .unwrap()
                .push(malformed.clone());
            for (entrypoint, result) in ["publish", "pre-push"].into_iter().zip(fixture.verify()) {
                if result.is_ok() {
                    accepted.push(format!("{entrypoint}: rules={rules}, omitted={malformed}"));
                }
            }
        }
    }
    assert!(
        accepted.is_empty(),
        "incomplete proof lists admitted: {accepted:?}"
    );
}

#[test]
fn adversary_unrelated_rules_and_explicit_null_unmerged_pr_remain_valid() {
    let mut fixture = Fixture::new();
    fixture
        .evidence
        .0
        .get_mut(RULES)
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(json!({"id":8,"name":"unrelated-protection"}));
    let mut unmerged = fixture.evidence.0[&format!("{ROOT}/pulls/1")].clone();
    unmerged["number"] = json!(2);
    unmerged["state"] = json!("open");
    unmerged.as_object_mut().unwrap().remove("merged");
    unmerged["merged_at"] = Value::Null;
    unmerged["merge_commit_sha"] = Value::Null;
    fixture
        .evidence
        .0
        .get_mut(&format!(
            "{ROOT}/commits/{}/pulls?per_page=100&page=1",
            fixture.merge
        ))
        .unwrap()
        .as_array_mut()
        .unwrap()
        .push(unmerged);
    fixture.assert_valid();
}

#[test]
fn adversary_published_merge_does_not_excuse_a_later_nonbot_committer() {
    for side_branch in [false, true] {
        let mut fixture = Fixture::new();
        fixture.assert_valid();
        let bad = commit(
            fixture.directory.path(),
            &fixture.tree,
            &[&fixture.merge],
            "Human <human@example.invalid>",
            "new nonbot commit",
        );
        fixture.candidate = if side_branch {
            commit(
                fixture.directory.path(),
                &fixture.tree,
                &[&fixture.candidate, &bad],
                &format!("{BOT_NAME} <{BOT_EMAIL}>"),
                "join",
            )
        } else {
            bad
        };
        for result in fixture.verify() {
            assert!(
                result.is_err(),
                "published proof exempted new nonbot history"
            );
        }
    }
}

#[test]
fn adversary_local_replacement_cannot_hide_a_nonbot_commit() {
    let mut fixture = Fixture::new();
    fixture.assert_valid();
    let bad = commit(
        fixture.directory.path(),
        &fixture.tree,
        &[&fixture.merge],
        "Human <human@example.invalid>",
        "bad",
    );
    let good = commit(
        fixture.directory.path(),
        &fixture.tree,
        &[&fixture.merge],
        &format!("{BOT_NAME} <{BOT_EMAIL}>"),
        "replacement",
    );
    git(
        fixture.directory.path(),
        &["update-ref", &format!("refs/replace/{bad}"), &good],
        b"",
    );
    fixture.candidate = bad;
    for result in fixture.verify() {
        assert!(result.is_err(), "replace ref forged direct bot identity");
    }
}

#[test]
fn adversary_remote_authority_is_not_reused_across_verification_calls() {
    let mut fixture = Fixture::new();
    fixture.assert_valid();
    fixture
        .evidence
        .0
        .get_mut(&format!("{ROOT}/rulesets/7"))
        .unwrap()["enforcement"] = json!("disabled");
    for result in fixture.verify() {
        assert!(
            result.is_err(),
            "previous verification cached authority across calls"
        );
    }
}

#[test]
fn adversary_duplicate_proof_on_later_page_is_not_ignored() {
    for rules in [true, false] {
        let mut fixture = Fixture::new();
        let prefix = if rules {
            format!("{ROOT}/rulesets?includes_parents=true&")
        } else {
            format!("{ROOT}/commits/{}/pulls?", fixture.merge)
        };
        let first = format!("{prefix}per_page=100&page=1");
        let second = format!("{prefix}per_page=100&page=2");
        let original = fixture.evidence.0[&first][0].clone();
        let items = fixture
            .evidence
            .0
            .get_mut(&first)
            .unwrap()
            .as_array_mut()
            .unwrap();
        for number in 2..=100 {
            items.push(if rules {
                json!({"id":number+100,"name":format!("unrelated-{number}")})
            } else {
                json!({"number":number,"merge_commit_sha":"1111111111111111111111111111111111111111"})
            });
        }
        fixture.evidence.0.insert(second.clone(), json!([]));
        fixture.assert_valid();
        fixture.evidence.0.insert(second, json!([original]));
        for result in fixture.verify() {
            assert!(
                result.is_err(),
                "later-page duplicate did not invalidate uniqueness"
            );
        }
    }
}
