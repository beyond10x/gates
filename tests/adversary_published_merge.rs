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

// Build the update proof through this adversary's fixture, independently of the
// implementation author's UpdateFixture. All API data remains synthetic.
fn updated_fixture(untrusted_prior: bool) -> (Fixture, String) {
    let mut fixture = Fixture::new();
    let bot = format!("{BOT_NAME} <{BOT_EMAIL}>");
    let base = commit(
        fixture.directory.path(),
        &fixture.tree,
        &[&fixture.baseline],
        &bot,
        "update base",
    );
    if untrusted_prior {
        let hidden = commit(
            fixture.directory.path(),
            &fixture.tree,
            &[&fixture.baseline],
            "Human <human@example.invalid>",
            "untrusted side ancestor",
        );
        fixture.topic = commit(
            fixture.directory.path(),
            &fixture.tree,
            &[&fixture.topic, &hidden],
            &bot,
            "bot join does not authorize the side ancestor",
        );
    }
    let update = commit(
        fixture.directory.path(),
        &fixture.tree,
        &[&fixture.topic, &base],
        "GitHub <noreply@github.com>",
        "branch update",
    );
    fixture.merge = commit(
        fixture.directory.path(),
        &fixture.tree,
        &[&base, &update],
        "GitHub <noreply@github.com>",
        "terminal merge",
    );
    fixture.candidate = commit(
        fixture.directory.path(),
        &fixture.tree,
        &[&fixture.merge],
        &bot,
        "candidate after update",
    );
    fixture.prove(update.clone(), fixture.topic.clone(), base.clone(), 2);
    fixture.prove(fixture.merge.clone(), base, update.clone(), 1);
    let pull = fixture.evidence.0[&format!("{ROOT}/pulls/1")].clone();
    fixture.evidence.0.insert(
        format!("{ROOT}/commits/{update}/pulls?per_page=100&page=1"),
        json!([pull]),
    );
    fixture.evidence.0.get_mut(REF).unwrap()["object"]["sha"] = json!(fixture.merge);
    (fixture, update)
}

#[test]
fn adversary_update_proof_never_excuses_a_nonbot_side_ancestor() {
    updated_fixture(false).0.assert_valid();
    let (fixture, _) = updated_fixture(true);
    for result in fixture.verify() {
        assert!(
            result.is_err(),
            "authenticated update exempted a nonbot side ancestor"
        );
        assert!(
            result.unwrap_err().to_string().contains("committer"),
            "refusal must identify the nonbot ancestor rather than missing synthetic evidence"
        );
    }
}

#[test]
fn adversary_update_and_terminal_pagination_cannot_hide_incomplete_or_ambiguous_proof() {
    for terminal in [false, true] {
        for mutation in ["missing-page", "duplicate", "malformed", "other-completed"] {
            let (mut fixture, update) = updated_fixture(false);
            let oid = if terminal { &fixture.merge } else { &update };
            let first = format!("{ROOT}/commits/{oid}/pulls?per_page=100&page=1");
            let second = format!("{ROOT}/commits/{oid}/pulls?per_page=100&page=2");
            let accepted = fixture.evidence.0[&first][0].clone();
            let mut page = vec![accepted.clone()];
            page.extend((2..=100).map(|number| json!({"number":number,"merge_commit_sha":null})));
            fixture.evidence.0.insert(first, json!(page));
            fixture.evidence.0.insert(second.clone(), json!([]));
            fixture.assert_valid();
            match mutation {
                "missing-page" => {
                    fixture.evidence.0.remove(&second);
                }
                "duplicate" => {
                    fixture.evidence.0.insert(second, json!([accepted]));
                }
                "malformed" => {
                    fixture.evidence.0.insert(second, json!([{"number":101}]));
                }
                "other-completed" => {
                    let mut other = accepted;
                    other["number"] = json!(101);
                    other["merge_commit_sha"] = json!(fixture.baseline);
                    fixture.evidence.0.insert(second, json!([other]));
                }
                _ => unreachable!(),
            }
            for result in fixture.verify() {
                assert!(
                    result.is_err(),
                    "terminal={terminal}, mutation={mutation} was accepted"
                );
            }
        }
    }
}

#[test]
fn adversary_each_update_and_terminal_commit_identity_field_is_required() {
    for terminal in [false, true] {
        for pointer in [
            "/sha",
            "/author/login",
            "/committer/login",
            "/commit/author/name",
            "/commit/author/email",
            "/commit/committer/name",
            "/commit/committer/email",
            "/commit/tree/sha",
            "/commit/verification/verified",
            "/commit/verification/reason",
            "/parents/0/sha",
            "/parents/1/sha",
        ] {
            let (mut fixture, update) = updated_fixture(false);
            fixture.assert_valid();
            let oid = if terminal { &fixture.merge } else { &update };
            let path = format!("{ROOT}/commits/{oid}");
            *fixture
                .evidence
                .0
                .get_mut(&path)
                .unwrap()
                .pointer_mut(pointer)
                .unwrap() = Value::Null;
            for result in fixture.verify() {
                assert!(
                    result.is_err(),
                    "terminal={terminal}, missing {pointer} was accepted"
                );
            }
        }
    }
}

// Squash merges proved by ancestry of the recorded base and a recomputed merge of the squash's
// parent and the pull request head (story squash-merge-moved-base). Built through this adversary's
// own fixture, independently of the implementation author's `SquashInputs`.

type Files<'a> = &'a [(&'a str, &'a [u8])];

const GITHUB: &str = "GitHub <noreply@github.com>";
const KEPT: (&str, &[u8]) = ("kept", b"as recorded\n");
const SECOND: (&str, &[u8]) = ("second", b"landed while the pull request was open\n");
const ADDED: (&str, &[u8]) = ("added", b"pull request 7\n");
const UNREVIEWED: (&str, &[u8]) = ("unreviewed", b"in neither input\n");
/// Four of the five merge options `Git::merge_tree` pins: all but `merge.renameLimit`, which the
/// fixtures leave to the repository's config so that they can compute the tree a steered rename
/// limit produces.
const PINS: [&str; 8] = [
    "-c",
    "merge.directoryRenames=conflict",
    "-c",
    "merge.renormalize=false",
    "-c",
    "merge.renames=true",
    "-c",
    "diff.renames=true",
];

fn bot() -> String {
    format!("{BOT_NAME} <{BOT_EMAIL}>")
}

fn lines(range: std::ops::RangeInclusive<u32>, tail: &str) -> Vec<u8> {
    let mut text: String = range.map(|n| format!("line {n}\n")).collect();
    text.push_str(tail);
    text.into_bytes()
}

/// A tree of regular files; a path `dir/name` becomes a subtree.
fn tree(root: &Path, files: Files) -> String {
    let mut entries = Vec::new();
    let mut dirs: BTreeMap<&str, Vec<(&str, &[u8])>> = BTreeMap::new();
    for (path, bytes) in files {
        match path.split_once('/') {
            Some((dir, rest)) => dirs.entry(dir).or_default().push((rest, bytes)),
            None => {
                let blob = git(root, &["hash-object", "-w", "--stdin"], bytes);
                entries.push(format!("100644 blob {blob}\t{path}\n"));
            }
        }
    }
    for (dir, inner) in dirs {
        entries.push(format!("040000 tree {}\t{dir}\n", tree(root, &inner)));
    }
    git(root, &["mktree"], entries.concat().as_bytes())
}

/// A tree from raw `git mktree` lines.
fn raw_tree(root: &Path, entries: &[String]) -> String {
    git(root, &["mktree"], entries.concat().as_bytes())
}

/// Git's merge of two commits with `PINS` and the repository's own config, so a rename limit the
/// repository sets is read here, unlike in `Git::merge_tree`.
fn merge_tree(root: &Path, first: &str, second: &str) -> (String, bool) {
    let output = Command::new("git")
        .args(["--no-replace-objects"])
        .args(PINS)
        .args(["merge-tree", "--write-tree", "--no-messages", first, second])
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .stderr(Stdio::null())
        .output()
        .unwrap();
    let clean = match output.status.code() {
        Some(0) => true,
        Some(1) => false,
        other => panic!("merge-tree failed: {other:?}"),
    };
    let tree = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .next()
        .unwrap()
        .to_owned();
    (tree, clean)
}

/// After the fixture's published merge: a bot commit `recorded` holding `base`, which pull request
/// 7 records as its base; the default branch then moves by a bot commit to `parent` holding
/// `moved`; the pull request head, cut from `recorded`, holds `head`.
struct Squash {
    f: Fixture,
    recorded: String,
    parent: String,
    head: String,
    squash: String,
}

impl Squash {
    fn new(base: Files, moved: Files, head: Files) -> Self {
        let f = Fixture::new();
        let root = f.directory.path().to_path_buf();
        let recorded = commit(&root, &tree(&root, base), &[&f.merge], &bot(), "recorded");
        let parent = commit(&root, &tree(&root, moved), &[&recorded], &bot(), "moved");
        let head = commit(&root, &tree(&root, head), &[&recorded], &bot(), "pull 7");
        Self {
            f,
            recorded,
            parent,
            head,
            squash: String::new(),
        }
    }

    /// The default branch took `SECOND` after the pull request, which adds `ADDED`, recorded it.
    fn moved() -> Self {
        Self::new(&[KEPT], &[KEPT, SECOND], &[KEPT, ADDED])
    }

    fn root(&self) -> &Path {
        self.f.directory.path()
    }

    fn files(&self, files: Files) -> String {
        tree(self.root(), files)
    }

    /// GitHub squashes pull request 7 onto `parent` and records `tree`. The record names
    /// `self.recorded` as its base and `self.head` as its head.
    fn land(&mut self, parent: &str, tree: &str) {
        let root = self.root().to_path_buf();
        let squash = commit(&root, tree, &[parent], GITHUB, "Add the topic (#7)");
        self.f.candidate = commit(&root, tree, &[&squash], &bot(), "candidate");
        let evidence = &mut self.f.evidence.0;
        evidence.get_mut(REF).unwrap()["object"]["sha"] = json!(squash);
        evidence.insert(
            format!("{ROOT}/commits/{squash}"),
            json!({
                "sha":squash,"author":{"login":BOT_NAME},"committer":{"login":"web-flow"},
                "commit":{"author":{"name":BOT_NAME,"email":BOT_EMAIL},
                    "committer":{"name":"GitHub","email":"noreply@github.com"},
                    "tree":{"sha":tree},"verification":{"verified":true,"reason":"valid"}},
                "parents":[{"sha":parent}]
            }),
        );
        let pr = json!({"number":7,"merged":true,"state":"closed","merge_commit_sha":squash,
            "merged_by":{"login":BOT_NAME},
            "head":{"sha":self.head,"repo":{"id":123,"full_name":REPOSITORY}},
            "base":{"ref":"main","sha":self.recorded,"repo":{"id":123,"full_name":REPOSITORY}}});
        evidence.insert(
            format!("{ROOT}/commits/{squash}/pulls?per_page=100&page=1"),
            json!([pr.clone()]),
        );
        evidence.insert(format!("{ROOT}/pulls/7"), pr);
        self.squash = squash;
    }

    /// Set `pointer` in the pull request record, in its detail and in its association entry.
    fn record(&mut self, pointer: &str, value: Value) {
        let list = format!("{ROOT}/commits/{}/pulls?per_page=100&page=1", self.squash);
        *self
            .f
            .evidence
            .0
            .get_mut(&format!("{ROOT}/pulls/7"))
            .unwrap()
            .pointer_mut(pointer)
            .unwrap() = value.clone();
        *self.f.evidence.0.get_mut(&list).unwrap()[0]
            .pointer_mut(pointer)
            .unwrap() = value;
    }

    /// The tree of `kept` and `second` as regular files, `name` as `kind` holding `bytes`, and
    /// one more raw entry.
    fn merge_with(&self, kind: &str, bytes: &[u8], name: &str, extra: Option<String>) -> String {
        let blob = |bytes: &[u8]| git(self.root(), &["hash-object", "-w", "--stdin"], bytes);
        let mut entries = vec![
            format!("{kind} {}\t{name}\n", blob(bytes)),
            format!("100644 blob {}\tkept\n", blob(KEPT.1)),
            format!("100644 blob {}\tsecond\n", blob(SECOND.1)),
        ];
        entries.extend(extra);
        raw_tree(self.root(), &entries)
    }

    /// The local merge of the parent and the head, asserted clean, landed as the squash.
    fn land_merge(&mut self) -> String {
        let (merged, clean) = merge_tree(self.root(), &self.parent, &self.head);
        assert!(clean, "fixture merge must be clean");
        let parent = self.parent.clone();
        self.land(&parent, &merged);
        merged
    }

    fn admitted(&self) -> bool {
        let results = self.f.verify();
        let admitted = results.iter().filter(|r| r.is_ok()).count();
        assert!(
            admitted == 0 || admitted == 2,
            "the entrypoints disagree: {results:?}"
        );
        admitted == 2
    }

    /// Both entrypoints refuse; the first refusal's full chain.
    fn refusal(&self, what: &str) -> String {
        let results = self.f.verify();
        for result in &results {
            assert!(result.is_err(), "{what}: admitted");
        }
        let [first, _] = results;
        format!("{:#}", first.unwrap_err())
    }
}

#[test]
fn adversary_squash_rename_limit_config_cannot_make_a_conflicting_squash_clean() {
    // Both sides rename the same two files to different names, with an edit each: an inexact
    // rename/rename conflict under Git's defaults. `merge.renameLimit` (or `diff.renameLimit`) in
    // the repository's own config turns inexact rename detection off, and the merge answers clean
    // with all four names. `Git::merge_tree` pins `merge.renames`/`diff.renames`, refuses
    // `merge.default` and `*.driver`, and leaves both rename limits to the repository.
    let a = lines(1..=40, "");
    let b = lines(101..=140, "");
    let (a1, b1) = (lines(1..=40, "head\n"), lines(101..=140, "head\n"));
    let (a2, b2) = (lines(1..=40, "base\n"), lines(101..=140, "base\n"));
    for key in ["merge.renameLimit", "diff.renameLimit"] {
        let mut s = Squash::new(
            &[("a", a.as_slice()), ("b", b.as_slice())],
            &[("a2", a2.as_slice()), ("b2", b2.as_slice())],
            &[("a1", a1.as_slice()), ("b1", b1.as_slice())],
        );
        let (_, clean) = merge_tree(s.root(), &s.parent, &s.head);
        assert!(!clean, "fixture must conflict under Git's defaults");
        git(s.root(), &["config", key, "1"], b"");
        let (steered, clean) = merge_tree(s.root(), &s.parent, &s.head);
        assert!(clean, "{key}=1 must make the fixture merge clean");
        let parent = s.parent.clone();
        s.land(&parent, &steered);
        let error = s.refusal(&format!("{key}=1 made a conflicting squash clean"));
        assert!(error.contains("conflicts"), "{key}: {error}");
    }
}

#[test]
fn adversary_rename_limit_config_cannot_make_a_conflicting_two_parent_merge_clean() {
    // The same steering against the two-parent proof, which shares `Git::merge_tree`: it shows
    // whether the gap predates the squash change.
    let a = lines(1..=40, "");
    let b = lines(101..=140, "");
    let (a1, b1) = (lines(1..=40, "head\n"), lines(101..=140, "head\n"));
    let (a2, b2) = (lines(1..=40, "base\n"), lines(101..=140, "base\n"));
    let mut s = Squash::new(
        &[("a", a.as_slice()), ("b", b.as_slice())],
        &[("a2", a2.as_slice()), ("b2", b2.as_slice())],
        &[("a1", a1.as_slice()), ("b1", b1.as_slice())],
    );
    let root = s.root().to_path_buf();
    git(&root, &["config", "merge.renameLimit", "1"], b"");
    let (steered, clean) = merge_tree(&root, &s.parent, &s.head);
    assert!(
        clean,
        "merge.renameLimit=1 must make the fixture merge clean"
    );
    let merge = commit(
        &root,
        &steered,
        &[&s.parent, &s.head],
        GITHUB,
        "Merge pull request #7 from example/topic",
    );
    s.f.tree = steered.clone();
    s.f.prove(merge.clone(), s.parent.clone(), s.head.clone(), 7);
    s.f.evidence.0.get_mut(REF).unwrap()["object"]["sha"] = json!(merge);
    s.f.candidate = commit(&root, &steered, &[&merge], &bot(), "candidate");
    let error = s.refusal("merge.renameLimit=1 made a conflicting merge clean");
    assert!(error.contains("conflicts"), "{error}");
}

#[test]
fn adversary_squash_whose_recorded_head_is_the_squash_or_below_it_refuses() {
    // The record's head is the input the squash is proved against. A head that is the squash
    // itself, or a commit that already contains it, makes `merge-tree(parent, head)` answer the
    // squash's own tree, so guard 3 proves the squash from itself: here a file in neither the
    // parent nor the pull request's real head is admitted.
    for below in [false, true] {
        let mut s = Squash::moved();
        let tampered = s.files(&[KEPT, SECOND, ADDED, UNREVIEWED]);
        let parent = s.parent.clone();
        s.land(&parent, &tampered);
        let head = if below {
            s.f.candidate.clone()
        } else {
            s.squash.clone()
        };
        s.record("/head/sha", json!(head));
        assert!(
            !s.admitted(),
            "a squash proved against itself was admitted (head below the squash: {below})"
        );
    }
}

#[test]
fn adversary_squash_forged_loose_head_tree_cannot_prove_an_extra_file() {
    // The local store is attacker-controlled data. `merge-tree` reads the head's tree without
    // checking its hash (`cat-file -p` and `parse_object` do check it), so a loose object file
    // holding another tree's bytes under the real head tree's name supplies the content the
    // squash added. Nothing in the squash proof reads the head tree through a checking path.
    let mut s = Squash::moved();
    let tampered = s.files(&[KEPT, SECOND, ADDED, UNREVIEWED]);
    let real = git(
        s.root(),
        &["rev-parse", &format!("{}^{{tree}}", s.head)],
        b"",
    );
    let forged = s.files(&[KEPT, ADDED, UNREVIEWED]);
    let object = |oid: &str| {
        s.root()
            .join(".git/objects")
            .join(&oid[..2])
            .join(&oid[2..])
    };
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(object(&real), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::copy(object(&forged), object(&real)).unwrap();
    let (merged, clean) = merge_tree(s.root(), &s.parent, &s.head);
    assert!(
        clean && merged == tampered,
        "fixture: the forged head tree must make the local merge the tampered tree"
    );
    let parent = s.parent.clone();
    s.land(&parent, &tampered);
    assert!(
        !s.admitted(),
        "a forged loose head tree proved a file in neither real input"
    );
}

#[test]
fn adversary_squash_parent_off_the_proved_line_is_walked_and_refused() {
    // Attack 1: the squash's parent is a side-line commit with a person as committer, reached
    // from the published head only through the second parent of a later bot merge. It passes
    // guard 1 (the recorded base is its ancestor) and its tree merges cleanly with the head. Every
    // parent of a walked commit is itself walked or below the baseline, so the walk refuses it.
    let mut s = Squash::moved();
    let root = s.root().to_path_buf();
    let side = commit(
        &root,
        &s.files(&[KEPT, SECOND]),
        &[&s.recorded],
        "Person <person@example.invalid>",
        "side line",
    );
    let (merged, clean) = merge_tree(&root, &side, &s.head);
    assert!(clean);
    s.land(&side, &merged);
    let joined = commit(
        &root,
        &merged,
        &[&s.parent, &s.squash],
        &bot(),
        "bot merge of the default branch and the squash",
    );
    s.f.evidence.0.get_mut(REF).unwrap()["object"]["sha"] = json!(joined);
    s.f.candidate = commit(&root, &merged, &[&joined], &bot(), "candidate");
    let error = s.refusal("a squash onto an unproved side-line parent");
    assert!(error.contains("committer"), "{error}");
}

#[test]
fn adversary_squash_tree_holding_more_than_the_pull_request_refuses() {
    // Attack 2: each tree differs from the clean merge of parent and head (`added`, `kept`,
    // `second`, all regular files) by one entry or one mode.
    type Variant = fn(&Squash) -> String;
    let variants: [(&str, Variant); 7] = [
        ("an extra file", |s| {
            s.files(&[KEPT, SECOND, ADDED, UNREVIEWED])
        }),
        (
            "the head's tree, dropping what the default branch took",
            |s| s.files(&[KEPT, ADDED]),
        ),
        ("the parent's tree, dropping the pull request", |s| {
            s.files(&[KEPT, SECOND])
        }),
        ("a changed mode", |s| {
            s.merge_with("100755 blob", ADDED.1, "added", None)
        }),
        ("a symlink in place of a file", |s| {
            s.merge_with("120000 blob", b"kept", "added", None)
        }),
        ("an extra gitlink", |s| {
            let module = format!("160000 commit {}\tmodule\n", s.head);
            s.merge_with("100644 blob", ADDED.1, "added", Some(module))
        }),
        ("an extra symlink", |s| {
            let target = git(s.root(), &["hash-object", "-w", "--stdin"], b"/etc/passwd");
            let link = format!("120000 blob {target}\tlink\n");
            s.merge_with("100644 blob", ADDED.1, "added", Some(link))
        }),
    ];
    for (what, variant) in variants {
        let mut s = Squash::moved();
        s.land_merge();
        assert!(s.admitted(), "{what}: control refused");
        let tree = variant(&s);
        let parent = s.parent.clone();
        s.land(&parent, &tree);
        let error = s.refusal(what);
        assert!(
            error
                .contains("squash tree is not the local merge of its parent and pull request head"),
            "{what}: refused for another reason: {error}"
        );
    }
}

#[test]
fn adversary_squash_content_in_a_path_both_sides_touched_must_be_the_merge() {
    // Both sides edit the same file in separate hunks; the merge holds both edits. A squash
    // holding one more changed line in that file refuses; the exact merge is admitted.
    let base = lines(1..=20, "");
    let moved = String::from_utf8(lines(1..=20, ""))
        .unwrap()
        .replace("line 2\n", "line 2 by the default branch\n");
    let head = String::from_utf8(lines(1..=20, ""))
        .unwrap()
        .replace("line 18\n", "line 18 by pull request 7\n");
    let mut s = Squash::new(
        &[("f", base.as_slice())],
        &[("f", moved.as_bytes())],
        &[("f", head.as_bytes())],
    );
    let merged = s.land_merge();
    assert!(s.admitted(), "control refused");
    let both = git(s.root(), &["cat-file", "-p", &format!("{merged}:f")], b"");
    assert!(both.contains("line 2 by the default branch") && both.contains("line 18 by pull"));
    let tampered = format!("{both}\n").replace("line 10\n", "line 10 unreviewed\n");
    let tree = s.files(&[("f", tampered.as_bytes())]);
    let parent = s.parent.clone();
    s.land(&parent, &tree);
    let error = s.refusal("one more line in a file both sides touched");
    assert!(
        error.contains("squash tree is not the local merge"),
        "{error}"
    );
}

#[test]
fn adversary_squash_heads_at_or_below_the_parent_are_admitted_only_as_the_parent_tree() {
    // A head equal to the parent or an ancestor of it (an empty squash) merges to the parent's
    // tree. That tree is admitted; one file more refuses.
    for head_is_parent in [true, false] {
        let mut s = Squash::moved();
        s.head = if head_is_parent {
            s.parent.clone()
        } else {
            s.recorded.clone()
        };
        let parent_tree = s.files(&[KEPT, SECOND]);
        let parent = s.parent.clone();
        s.land(&parent, &parent_tree);
        assert!(
            s.admitted(),
            "an empty squash refused (head is parent: {head_is_parent})"
        );
        let extra = s.files(&[KEPT, SECOND, UNREVIEWED]);
        s.land(&parent, &extra);
        let error = s.refusal("an empty squash with an extra file");
        assert!(
            error.contains("squash tree is not the local merge"),
            "{error}"
        );
    }
}

#[test]
fn adversary_squash_unrelated_head_refuses() {
    let mut s = Squash::moved();
    let root = s.root().to_path_buf();
    s.head = commit(&root, &s.files(&[ADDED]), &[], &bot(), "unrelated root");
    let merged = s.files(&[KEPT, SECOND, ADDED]);
    let parent = s.parent.clone();
    s.land(&parent, &merged);
    let error = s.refusal("a squash of an unrelated head");
    assert!(error.contains("merge-tree"), "{error}");
}

#[test]
fn adversary_squash_criss_cross_head_is_admitted_only_as_the_recursive_merge() {
    // The parent and the head each merge the same two side commits in opposite order, so they
    // have two merge bases and Git merges a virtual base first.
    let mut s = Squash::moved();
    let root = s.root().to_path_buf();
    let x = commit(
        &root,
        &s.files(&[KEPT, ("x", b"x\n")]),
        &[&s.recorded],
        &bot(),
        "x",
    );
    let y = commit(
        &root,
        &s.files(&[KEPT, ("y", b"y\n")]),
        &[&s.recorded],
        &bot(),
        "y",
    );
    let both = s.files(&[KEPT, ("x", b"x\n"), ("y", b"y\n")]);
    s.parent = commit(&root, &both, &[&x, &y], &bot(), "x and y");
    s.head = commit(
        &root,
        &s.files(&[KEPT, ADDED, ("x", b"x\n"), ("y", b"y\n")]),
        &[&y, &x],
        &bot(),
        "y and x, then pull 7",
    );
    let bases = git(&root, &["merge-base", "--all", &s.parent, &s.head], b"");
    assert_eq!(bases.lines().count(), 2, "fixture must be criss-cross");
    s.land_merge();
    assert!(s.admitted(), "the recursive merge refused");
    let extra = s.files(&[KEPT, ADDED, ("x", b"x\n"), ("y", b"y\n"), UNREVIEWED]);
    let parent = s.parent.clone();
    s.land(&parent, &extra);
    let error = s.refusal("a criss-cross squash with an extra file");
    assert!(
        error.contains("squash tree is not the local merge"),
        "{error}"
    );
}

#[test]
fn adversary_squash_directory_rename_resolved_as_a_move_refuses() {
    // The default branch renames `a/` to `b/`; the pull request adds `a/y`. With directory renames
    // pinned to `conflict` the local merge conflicts, so a squash that moved `y` under `b/` refuses
    // even though it holds only the two inputs' content.
    let mut s = Squash::new(
        &[("a/x", b"x\n")],
        &[("b/x", b"x\n")],
        &[("a/x", b"x\n"), ("a/y", b"y\n")],
    );
    let (_, clean) = merge_tree(s.root(), &s.parent, &s.head);
    assert!(
        !clean,
        "fixture must conflict with directory renames pinned"
    );
    let moved = s.files(&[("b/x", b"x\n"), ("b/y", b"y\n")]);
    let parent = s.parent.clone();
    s.land(&parent, &moved);
    let error = s.refusal("a squash whose directory rename was resolved");
    assert!(error.contains("conflicts"), "{error}");
}

#[test]
fn adversary_squash_recorded_base_that_is_no_ancestor_commit_refuses() {
    // Attack 3: well-formed ids that are not the parent or a commit below it. The squash itself
    // as the base kills a guard-1 mutant that asks about the squash instead of its parent.
    type Base = fn(&Squash) -> String;
    let cases: [(&str, Base); 5] = [
        ("the recorded base's tree", |s| {
            git(
                s.root(),
                &["rev-parse", &format!("{}^{{tree}}", s.recorded)],
                b"",
            )
        }),
        ("a blob", |s| {
            git(s.root(), &["hash-object", "-w", "--stdin"], KEPT.1)
        }),
        ("the squash itself", |s| s.squash.clone()),
        ("the unmerged pull request head", |s| s.head.clone()),
        ("a commit above the squash", |s| s.f.candidate.clone()),
    ];
    for (what, base) in cases {
        let mut s = Squash::moved();
        s.land_merge();
        assert!(s.admitted(), "{what}: control refused");
        let base = base(&s);
        s.record("/base/sha", json!(base));
        let error = s.refusal(what);
        assert!(
            error.contains("squash merge parent does not descend from the pull request base"),
            "{what}: refused for another reason: {error}"
        );
    }
}

#[test]
fn adversary_squash_head_through_a_tag_or_a_replace_ref_refuses() {
    // Attack 4: the record's head named through an annotated tag object, and a replace ref that
    // swaps the head for a commit already holding the squash's extra file.
    let mut s = Squash::moved();
    s.land_merge();
    let root = s.root().to_path_buf();
    let tag = git(
        &root,
        &["mktag"],
        format!(
            "object {}\ntype commit\ntag head\ntagger {} 1700000000 +0000\n\nhead\n",
            s.head,
            bot()
        )
        .as_bytes(),
    );
    s.record("/head/sha", json!(tag));
    let error = s.refusal("a head named through a tag object");
    assert!(error.contains("is not a commit"), "{error}");

    let mut s = Squash::moved();
    let tampered = s.files(&[KEPT, SECOND, ADDED, UNREVIEWED]);
    let parent = s.parent.clone();
    s.land(&parent, &tampered);
    let swap = commit(
        s.root(),
        &s.files(&[KEPT, ADDED, UNREVIEWED]),
        &[&s.recorded],
        &bot(),
        "replacement head",
    );
    git(
        s.root(),
        &["update-ref", &format!("refs/replace/{}", s.head), &swap],
        b"",
    );
    let error = s.refusal("a head swapped by a replace ref");
    assert!(
        error.contains("squash tree is not the local merge"),
        "{error}"
    );
}

#[test]
fn adversary_squash_partial_clone_without_blobs_refuses_rather_than_admits() {
    // Attack 4: the default branch renames `a` with an edit; the pull request edits `a`. Git
    // needs blob content to find the inexact rename. In a `--filter=blob:none` clone with lazy
    // fetching off, after the fetch the refusal for an absent head names, the merge cannot read
    // those blobs. It must refuse, never answer a merge computed without them.
    let a = lines(1..=40, "");
    let renamed = lines(1..=40, "moved\n");
    let edited = String::from_utf8(lines(1..=40, ""))
        .unwrap()
        .replace("line 3\n", "line 3 by pull request 7\n");
    let mut s = Squash::new(
        &[("a", a.as_slice())],
        &[("a2", renamed.as_slice())],
        &[("a", edited.as_bytes())],
    );
    s.land_merge();
    assert!(s.admitted(), "control refused on the full store");
    let source = s.root().to_path_buf();
    for key in ["uploadpack.allowFilter", "uploadpack.allowAnySHA1InWant"] {
        git(&source, &["config", key, "true"], b"");
    }
    git(
        &source,
        &["update-ref", "refs/heads/main", &s.f.candidate],
        b"",
    );
    git(&source, &["update-ref", "refs/pull/7/head", &s.head], b"");
    let clone = tempfile::tempdir().unwrap();
    git(
        clone.path(),
        &[
            "clone",
            "-q",
            "--filter=blob:none",
            "--no-checkout",
            &format!("file://{}", source.display()),
            ".",
        ],
        b"",
    );
    git(
        clone.path(),
        &["fetch", "-q", "origin", "refs/pull/7/head"],
        b"",
    );
    let _source = std::mem::replace(&mut s.f.directory, clone);
    let error = s.refusal("a squash merged without the blobs rename detection needs");
    assert!(error.contains("merge-tree"), "{error}");
}

#[test]
fn adversary_squash_head_commits_are_not_walked_on_a_public_repository() {
    // Attack 4, who proves the head: a head committed by a person is not walked, so on a public
    // repository the squash is admitted on the branch authority alone (the comment at the squash
    // proof says so); on a private repository the shape refuses.
    let mut s = Squash::moved();
    let root = s.root().to_path_buf();
    s.head = commit(
        &root,
        &s.files(&[KEPT, ADDED]),
        &[&s.recorded],
        "Person <person@example.invalid>",
        "person's head",
    );
    s.land_merge();
    assert!(s.admitted(), "public squash of a person's head");
    let root_response = s.f.evidence.0.get_mut(ROOT).unwrap();
    root_response["private"] = json!(true);
    root_response["visibility"] = json!("private");
    let results = s.f.verify();
    assert!(
        results.iter().all(|r| r.is_err()),
        "private squash admitted"
    );
}

// Round 2: the guards added after the first pass (`Git::is_ancestor`, `ensure_merge_input` for
// the head, the base commit check, the `merge.renameLimit` pin, the partial-clone remedy and the
// named fetch).

/// Writes a commit-graph file for the history of `tips`, as `git gc` or `git commit-graph write`
/// leaves one in a clone, and then rewrites the entry of `commit`: its root tree to `tree`, its
/// first parent to `parent`. The file's trailing checksum is left as Git wrote it.
fn forge_commit_graph(
    root: &Path,
    tips: &[&str],
    commit: &str,
    tree: Option<&str>,
    parent: Option<&str>,
) {
    let tips = format!("{}\n", tips.join("\n"));
    git(
        root,
        &["commit-graph", "write", "--stdin-commits", "--no-progress"],
        tips.as_bytes(),
    );
    let path = root.join(".git/objects/info/commit-graph");
    let mut graph = std::fs::read(&path).unwrap();
    assert_eq!(&graph[..4], b"CGPH", "fixture: commit-graph header");
    let chunk = |id: &[u8; 4]| -> usize {
        (0..usize::from(graph[6]))
            .map(|i| 8 + 12 * i)
            .find(|at| &graph[*at..*at + 4] == id)
            .map(|at| u64::from_be_bytes(graph[at + 4..at + 12].try_into().unwrap()) as usize)
            .expect("fixture: commit-graph chunk")
    };
    let (fanout, list, data) = (chunk(b"OIDF"), chunk(b"OIDL"), chunk(b"CDAT"));
    let count = u32::from_be_bytes(
        graph[fanout + 255 * 4..fanout + 256 * 4]
            .try_into()
            .unwrap(),
    ) as usize;
    let position = |oid: &str| -> usize {
        let raw = hex::decode(oid).unwrap();
        (0..count)
            .find(|i| graph[list + 20 * i..list + 20 * i + 20] == raw[..])
            .expect("fixture: commit in the commit-graph")
    };
    let entry = data + 36 * position(commit);
    let parent = parent.map(position);
    if let Some(tree) = tree {
        graph[entry..entry + 20].copy_from_slice(&hex::decode(tree).unwrap());
    }
    if let Some(parent) = parent {
        graph[entry + 20..entry + 24]
            .copy_from_slice(&u32::try_from(parent).unwrap().to_be_bytes());
    }
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::write(&path, graph).unwrap();
}

#[test]
fn adversary_squash_commit_graph_cannot_hide_that_the_head_contains_the_squash() {
    // B1: the recorded head is two commits above the squash and holds the squash's extra file.
    // A commit-graph entry that names the recorded base as the first parent of the commit between
    // them makes `merge-base --is-ancestor <squash> <head>` answer 1 ("no"), and the merge base of
    // parent and head becomes the recorded base, so the local merge is the tampered tree. The
    // commit-graph is a file in the local store, like the grafts and shallow files `Git::new`
    // refuses; Git reads parents from it instead of from the commit objects.
    let mut s = Squash::moved();
    let root = s.root().to_path_buf();
    let tampered = s.files(&[KEPT, SECOND, ADDED, UNREVIEWED]);
    let parent = s.parent.clone();
    s.land(&parent, &tampered);
    let between = commit(&root, &tampered, &[&s.squash], &bot(), "between");
    let head = commit(&root, &tampered, &[&between], &bot(), "above the squash");
    s.record("/head/sha", json!(head));
    assert!(!s.admitted(), "control: a head above the squash refused");
    forge_commit_graph(
        &root,
        &[&s.f.candidate, &head],
        &between,
        None,
        Some(&s.recorded),
    );
    let (merged, clean) = merge_tree(&root, &s.parent, &head);
    assert!(
        clean && merged == tampered,
        "fixture: the commit-graph must make the local merge the tampered tree"
    );
    assert!(
        !s.admitted(),
        "a forged commit-graph hid that the head contains its own squash"
    );
}

#[test]
fn adversary_commit_graph_cannot_hide_a_person_commit_from_the_ancestry_walk() {
    // Same file, the walk itself: `rev-list baseline..head` reads parents from the commit-graph,
    // so an entry that skips a person's commit removes it from the walk, and nothing else in
    // `published_merge::verify` reads that commit. No squash is involved.
    let mut fixture = Fixture::new();
    let root = fixture.directory.path().to_path_buf();
    let person = commit(
        &root,
        &fixture.tree,
        &[&fixture.merge],
        "Person <person@example.invalid>",
        "person",
    );
    let between = commit(&root, &fixture.tree, &[&person], &bot(), "between");
    fixture.candidate = commit(&root, &fixture.tree, &[&between], &bot(), "candidate");
    for result in fixture.verify() {
        assert!(result.is_err(), "control: a person's commit admitted");
    }
    forge_commit_graph(
        &root,
        &[&fixture.candidate],
        &between,
        None,
        Some(&fixture.merge),
    );
    let listed = git(
        &root,
        &[
            "rev-list",
            &format!("{}..{}", fixture.baseline, fixture.candidate),
        ],
        b"",
    );
    assert!(
        !listed.contains(&person),
        "fixture: the commit-graph must hide the person's commit from rev-list"
    );
    for result in fixture.verify() {
        assert!(
            result.is_err(),
            "a forged commit-graph hid a person's commit from the walk"
        );
    }
}

#[test]
fn adversary_squash_commit_graph_tree_of_the_head_is_not_what_merge_tree_reads() {
    // B2, held: the commit-graph also stores each commit's root tree. With the head's entry naming
    // a tree that holds the extra file, `merge-tree` still reads the head's tree from the head's
    // own (hash-checked) object, because it resolves its two arguments with `parse_object`; the
    // squash refuses.
    let mut s = Squash::moved();
    let root = s.root().to_path_buf();
    let tampered = s.files(&[KEPT, SECOND, ADDED, UNREVIEWED]);
    let extra = s.files(&[KEPT, ADDED, UNREVIEWED]);
    let parent = s.parent.clone();
    s.land(&parent, &tampered);
    let head = s.head.clone();
    forge_commit_graph(&root, &[&s.f.candidate, &head], &head, Some(&extra), None);
    let error = s.refusal("a head whose commit-graph entry names another tree");
    assert!(
        error.contains("squash tree is not the local merge"),
        "{error}"
    );
}

#[test]
fn adversary_squash_forged_head_commit_object_refuses() {
    // B2: the head's loose commit object holds another commit's bytes (one whose tree is the
    // tampered squash tree). `cat-file -t` reads only its header and answers "commit";
    // `ensure_merge_input` peels the head with a hash check and refuses.
    let mut s = Squash::moved();
    let root = s.root().to_path_buf();
    let tampered = s.files(&[KEPT, SECOND, ADDED, UNREVIEWED]);
    let parent = s.parent.clone();
    s.land(&parent, &tampered);
    let donor = commit(&root, &tampered, &[&s.recorded], &bot(), "donor");
    let object = |oid: &str| root.join(".git/objects").join(&oid[..2]).join(&oid[2..]);
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(object(&s.head), std::fs::Permissions::from_mode(0o644)).unwrap();
    std::fs::copy(object(&donor), object(&s.head)).unwrap();
    assert_eq!(
        git(&root, &["cat-file", "-t", &s.head], b""),
        "commit",
        "fixture: the forged object must still read as a commit"
    );
    let error = s.refusal("a forged head commit object");
    assert!(error.contains("Git rev-parse failed"), "{error}");
}

#[test]
fn adversary_squash_rename_limit_from_included_config_cannot_lift_the_pin() {
    // B4, held: `merge.renameLimit=1` reached through `include.path` and through `includeIf`
    // in the repository's config. The `-c` pin wins over both.
    let a = lines(1..=40, "");
    let b = lines(101..=140, "");
    let (a1, b1) = (lines(1..=40, "head\n"), lines(101..=140, "head\n"));
    let (a2, b2) = (lines(1..=40, "base\n"), lines(101..=140, "base\n"));
    for conditional in [false, true] {
        let mut s = Squash::new(
            &[("a", a.as_slice()), ("b", b.as_slice())],
            &[("a2", a2.as_slice()), ("b2", b2.as_slice())],
            &[("a1", a1.as_slice()), ("b1", b1.as_slice())],
        );
        let root = s.root().to_path_buf();
        std::fs::write(
            root.join(".git/extra.config"),
            "[merge]\n\trenameLimit = 1\n",
        )
        .unwrap();
        let key = if conditional {
            format!("includeIf.gitdir:{}/.git.path", root.display())
        } else {
            "include.path".to_owned()
        };
        git(&root, &["config", &key, "extra.config"], b"");
        let (steered, clean) = merge_tree(&root, &s.parent, &s.head);
        assert!(
            clean,
            "fixture: the included limit must make the merge clean"
        );
        let parent = s.parent.clone();
        s.land(&parent, &steered);
        let error = s.refusal("an included rename limit");
        assert!(
            error.contains("conflicts"),
            "conditional: {conditional}: {error}"
        );
    }
}

#[test]
fn adversary_squash_hand_made_pull_ref_does_not_change_the_verdict() {
    // B6, held: a local `refs/pull/7/head` created by hand and pointing at a commit that holds the
    // squash's extra file. The gate reads the head from the record, so the ref changes nothing:
    // an absent head still refuses and names the fetch, a real squash is still admitted, and a
    // tampered squash still refuses.
    let mut s = Squash::moved();
    let root = s.root().to_path_buf();
    let tampered = s.files(&[KEPT, SECOND, ADDED, UNREVIEWED]);
    let decoy = commit(&root, &tampered, &[&s.recorded], &bot(), "decoy");
    git(&root, &["update-ref", "refs/pull/7/head", &decoy], b"");
    s.land_merge();
    assert!(s.admitted(), "a real squash refused beside a decoy ref");
    s.record(
        "/head/sha",
        json!("0123456789abcdef0123456789abcdef01234567"),
    );
    let error = s.refusal("an absent head beside a decoy ref");
    assert!(
        error.contains("is not in the local object store"),
        "{error}"
    );
    let mut s = Squash::moved();
    let root = s.root().to_path_buf();
    let tampered = s.files(&[KEPT, SECOND, ADDED, UNREVIEWED]);
    let decoy = commit(&root, &tampered, &[&s.recorded], &bot(), "decoy");
    git(&root, &["update-ref", "refs/pull/7/head", &decoy], b"");
    let parent = s.parent.clone();
    s.land(&parent, &tampered);
    let error = s.refusal("a tampered squash beside a decoy ref");
    assert!(
        error.contains("squash tree is not the local merge"),
        "{error}"
    );
}
