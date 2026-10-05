use anyhow::{Context, Result};
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    git::Git,
    policy::{Policy, Repository},
    published_merge::AuthenticatedRead,
};
use serde_json::{Value, json};
use std::{
    cell::Cell,
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

#[derive(Default)]
struct Evidence {
    responses: BTreeMap<String, Value>,
    calls: Cell<usize>,
}
impl AuthenticatedRead for Evidence {
    fn get(&self, path: &str) -> Result<Value> {
        self.calls.set(self.calls.get() + 1);
        self.responses
            .get(path)
            .cloned()
            .context("fixture API unavailable")
    }
}

struct Fixture {
    dir: TempDir,
    baseline: String,
    topic: String,
    merge: String,
    candidate: String,
    tree: String,
    policy: Policy,
    api: Evidence,
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
        let merge = commit(dir.path(), &tree, &[&baseline, &topic], true, "merge");
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
        let mut api = Evidence::default();
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
        let mut fixture = Self {
            dir,
            baseline,
            topic,
            merge,
            candidate,
            tree,
            policy,
            api,
        };
        fixture.prove_merge(
            fixture.merge.clone(),
            fixture.baseline.clone(),
            fixture.topic.clone(),
            1,
        );
        fixture
    }

    fn prove_merge(&mut self, merge: String, first: String, head: String, number: u64) {
        self.api.responses.insert(format!("{ROOT}/commits/{merge}"), json!({
            "sha":merge,"author":{"login":BOT_NAME},"committer":{"login":"web-flow"},
            "commit":{"author":{"name":BOT_NAME,"email":BOT_EMAIL},"committer":{"name":"GitHub","email":"noreply@github.com"},"tree":{"sha":self.tree},"verification":{"verified":true,"reason":"valid"}},
            "parents":[{"sha":first},{"sha":head}]
        }));
        let pr = json!({"number":number,"state":"closed","merged":true,"merge_commit_sha":merge,"merged_by":{"login":BOT_NAME},"head":{"sha":head,"repo":{"full_name":REPOSITORY,"id":123}},"base":{"ref":"main","repo":{"full_name":REPOSITORY,"id":123}}});
        self.api.responses.insert(
            format!("{ROOT}/commits/{merge}/pulls?per_page=100&page=1"),
            json!([pr.clone()]),
        );
        self.api
            .responses
            .insert(format!("{ROOT}/pulls/{number}"), pr);
    }

    fn verify(&self) -> Result<()> {
        let git = Git::new(self.dir.path())?;
        let publication = b10x_gates::delivery::verify_publication(
            &git,
            &self.policy,
            REPOSITORY,
            &self.candidate,
            &self.api,
        );
        let push = b10x_gates::hooks::verify_pre_push(
            &git,
            &self.policy,
            REPOSITORY,
            &self.candidate,
            &self.api,
        );
        assert_eq!(
            publication.is_ok(),
            push.is_ok(),
            "publication and pre-push disagree"
        );
        publication
    }

    fn remote_commit(&mut self) -> &mut Value {
        self.api
            .responses
            .get_mut(&format!("{ROOT}/commits/{}", self.merge))
            .unwrap()
    }

    fn pr(&mut self) -> &mut Value {
        self.api
            .responses
            .get_mut(&format!("{ROOT}/pulls/1"))
            .unwrap()
    }

    fn authority(&mut self) -> &mut Value {
        self.api.responses.get_mut(AUTHORITY).unwrap()
    }

    fn replace_merge(&mut self, tree: &str, parents: &[&str]) {
        self.merge = commit(self.dir.path(), tree, parents, true, "replacement merge");
        self.candidate = commit(
            self.dir.path(),
            tree,
            &[&self.merge],
            false,
            "replacement candidate",
        );
        self.api.responses.get_mut(REF).unwrap()["object"]["sha"] = json!(self.merge);
        self.tree = tree.into();
        if parents.len() == 2 {
            self.prove_merge(self.merge.clone(), parents[0].into(), parents[1].into(), 1);
        }
    }
}

struct UpdateFixture {
    dir: TempDir,
    prior_head: String,
    base: String,
    update: String,
    merge: String,
    candidate: String,
    tree: String,
    policy: Policy,
    api: Evidence,
}

impl UpdateFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        git(
            dir.path(),
            &["init", "-q", "--initial-branch=main", "--template="],
            b"",
        );
        let blob = git(dir.path(), &["hash-object", "-w", "--stdin"], b"accepted\n");
        let tree = git(
            dir.path(),
            &["mktree"],
            format!("100644 blob {blob}\taccepted\n").as_bytes(),
        );
        let baseline = commit(dir.path(), &tree, &[], false, "baseline");
        let prior_head = commit(dir.path(), &tree, &[&baseline], false, "prior pull head");
        let base = commit(dir.path(), &tree, &[&baseline], false, "updated base");
        let update = commit(
            dir.path(),
            &tree,
            &[&prior_head, &base],
            true,
            "GitHub update branch",
        );
        let merge = commit(
            dir.path(),
            &tree,
            &[&base, &update],
            true,
            "GitHub final merge",
        );
        let candidate = commit(dir.path(), &tree, &[&merge], false, "candidate");
        git(
            dir.path(),
            &["update-ref", "refs/heads/main", &candidate],
            b"",
        );
        let policy = Policy {
            version: 1,
            nonce: "synthetic-update-branch-policy".into(),
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
        let mut api = Evidence::default();
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
        let mut fixture = Self {
            dir,
            prior_head,
            base,
            update,
            merge,
            candidate,
            tree,
            policy,
            api,
        };
        fixture.prove_commit(
            fixture.update.clone(),
            &fixture.update_parents(),
            fixture.tree.clone(),
        );
        fixture.prove_commit(
            fixture.merge.clone(),
            &fixture.merge_parents(),
            fixture.tree.clone(),
        );
        let pull = fixture.pull();
        fixture.api.responses.insert(
            format!(
                "{ROOT}/commits/{}/pulls?per_page=100&page=1",
                fixture.update
            ),
            json!([pull.clone()]),
        );
        fixture.api.responses.insert(
            format!("{ROOT}/commits/{}/pulls?per_page=100&page=1", fixture.merge),
            json!([pull.clone()]),
        );
        fixture
            .api
            .responses
            .insert(format!("{ROOT}/pulls/404"), pull);
        fixture
    }

    fn update_parents(&self) -> [String; 2] {
        [self.prior_head.clone(), self.base.clone()]
    }

    fn merge_parents(&self) -> [String; 2] {
        [self.base.clone(), self.update.clone()]
    }

    fn prove_commit(&mut self, oid: String, parents: &[String], tree: String) {
        let parents: Vec<_> = parents.iter().map(|sha| json!({"sha":sha})).collect();
        self.api.responses.insert(format!("{ROOT}/commits/{oid}"), json!({
            "sha":oid,"author":{"login":BOT_NAME},"committer":{"login":"web-flow"},
            "commit":{"author":{"name":BOT_NAME,"email":BOT_EMAIL},"committer":{"name":"GitHub","email":"noreply@github.com"},"tree":{"sha":tree},"verification":{"verified":true,"reason":"valid"}},
            "parents":parents
        }));
    }

    fn pull(&self) -> Value {
        self.pull_with_head(&self.update)
    }

    fn pull_with_head(&self, head: &str) -> Value {
        json!({"number":404,"state":"closed","merged":true,"merge_commit_sha":self.merge,
            "merged_by":{"login":BOT_NAME},
            "head":{"sha":head,"repo":{"full_name":REPOSITORY,"id":123}},
            "base":{"ref":"main","repo":{"full_name":REPOSITORY,"id":123}}})
    }

    fn update_remote(&mut self) -> &mut Value {
        self.api
            .responses
            .get_mut(&format!("{ROOT}/commits/{}", self.update))
            .unwrap()
    }

    fn merge_remote(&mut self) -> &mut Value {
        self.api
            .responses
            .get_mut(&format!("{ROOT}/commits/{}", self.merge))
            .unwrap()
    }

    fn update_pulls(&mut self) -> &mut Value {
        self.api
            .responses
            .get_mut(&format!(
                "{ROOT}/commits/{}/pulls?per_page=100&page=1",
                self.update
            ))
            .unwrap()
    }

    fn merge_pulls(&mut self) -> &mut Value {
        self.api
            .responses
            .get_mut(&format!(
                "{ROOT}/commits/{}/pulls?per_page=100&page=1",
                self.merge
            ))
            .unwrap()
    }

    fn pr(&mut self) -> &mut Value {
        self.api
            .responses
            .get_mut(&format!("{ROOT}/pulls/404"))
            .unwrap()
    }

    fn replace_update_raw(&mut self, author: &str, committer: &str, parents: &[String]) {
        let mut raw = format!("tree {}\n", self.tree);
        for parent in parents {
            raw.push_str(&format!("parent {parent}\n"));
        }
        raw.push_str(&format!(
            "author {author}\ncommitter {committer}\n\nreplacement update\n"
        ));
        self.update = git(
            self.dir.path(),
            &[
                "hash-object",
                "--literally",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ],
            raw.as_bytes(),
        );
        self.replace_final(
            &self.tree.clone(),
            &[self.base.clone(), self.update.clone()],
        );
        self.prove_commit(self.update.clone(), parents, self.tree.clone());
        let pull = self.pull();
        self.api.responses.insert(
            format!("{ROOT}/commits/{}/pulls?per_page=100&page=1", self.update),
            json!([pull]),
        );
    }

    fn replace_final(&mut self, tree: &str, parents: &[String]) {
        self.replace_final_with_head(tree, parents, &self.update.clone());
    }

    fn replace_final_with_head(&mut self, tree: &str, parents: &[String], head: &str) {
        let parent_refs: Vec<_> = parents.iter().map(String::as_str).collect();
        self.merge = commit(
            self.dir.path(),
            tree,
            &parent_refs,
            true,
            "replacement final merge",
        );
        self.candidate = commit(
            self.dir.path(),
            tree,
            &[&self.merge],
            false,
            "replacement candidate",
        );
        git(
            self.dir.path(),
            &["update-ref", "refs/heads/main", &self.candidate],
            b"",
        );
        self.api.responses.get_mut(REF).unwrap()["object"]["sha"] = json!(self.merge);
        self.prove_commit(self.merge.clone(), parents, tree.to_owned());
        let pull = self.pull_with_head(head);
        self.api.responses.insert(
            format!("{ROOT}/commits/{}/pulls?per_page=100&page=1", self.update),
            json!([pull.clone()]),
        );
        self.api.responses.insert(
            format!("{ROOT}/commits/{}/pulls?per_page=100&page=1", self.merge),
            json!([pull.clone()]),
        );
        self.api.responses.insert(format!("{ROOT}/pulls/404"), pull);
    }

    fn replace_final_raw(&mut self, tree: &str, parents: &[String], author: &str, committer: &str) {
        let mut raw = format!("tree {tree}\n");
        for parent in parents {
            raw.push_str(&format!("parent {parent}\n"));
        }
        raw.push_str(&format!(
            "author {author}\ncommitter {committer}\n\nreplacement final merge\n"
        ));
        self.merge = git(
            self.dir.path(),
            &[
                "hash-object",
                "--literally",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ],
            raw.as_bytes(),
        );
        self.candidate = commit(
            self.dir.path(),
            tree,
            &[&self.merge],
            false,
            "replacement candidate",
        );
        git(
            self.dir.path(),
            &["update-ref", "refs/heads/main", &self.candidate],
            b"",
        );
        self.api.responses.get_mut(REF).unwrap()["object"]["sha"] = json!(self.merge);
        self.prove_commit(self.merge.clone(), parents, tree.to_owned());
        let pull = self.pull();
        self.api.responses.insert(
            format!("{ROOT}/commits/{}/pulls?per_page=100&page=1", self.update),
            json!([pull.clone()]),
        );
        self.api.responses.insert(
            format!("{ROOT}/commits/{}/pulls?per_page=100&page=1", self.merge),
            json!([pull.clone()]),
        );
        self.api.responses.insert(format!("{ROOT}/pulls/404"), pull);
    }

    fn verify(&self) -> [Result<()>; 2] {
        let git = Git::new(self.dir.path()).unwrap();
        [
            b10x_gates::delivery::verify_publication(
                &git,
                &self.policy,
                REPOSITORY,
                &self.candidate,
                &self.api,
            ),
            b10x_gates::hooks::verify_pre_push(
                &git,
                &self.policy,
                REPOSITORY,
                &self.candidate,
                &self.api,
            ),
        ]
    }

    fn assert_refused(&self, mutation: &str) {
        for (entrypoint, result) in ["verify_publication", "verify_pre_push"]
            .into_iter()
            .zip(self.verify())
        {
            assert!(result.is_err(), "{mutation} admitted through {entrypoint}");
        }
    }
}

#[test]
fn exact_update_branch_then_final_merge_is_admitted_by_both_entrypoints() {
    let fixture = UpdateFixture::new();
    let failures: Vec<_> = ["verify_publication", "verify_pre_push"]
        .into_iter()
        .zip(fixture.verify())
        .filter_map(|(entrypoint, result)| result.err().map(|error| (entrypoint, error)))
        .collect();
    assert!(
        failures.is_empty(),
        "exact authenticated update graph refused: {failures:#?}"
    );
}

#[test]
fn update_branch_local_and_remote_commit_identity_is_exact() {
    macro_rules! refusal {
        ($label:literal, $change:expr) => {{
            let mut fixture = UpdateFixture::new();
            ($change)(&mut fixture);
            fixture.assert_refused($label);
        }};
    }

    refusal!("local update author", |f: &mut UpdateFixture| {
        let parents = f.update_parents();
        f.replace_update_raw(
            "Human <human@example.invalid> 1700000000 +0000",
            "GitHub <noreply@github.com> 1700000000 +0000",
            &parents,
        );
    });
    refusal!("local update committer", |f: &mut UpdateFixture| {
        let parents = f.update_parents();
        f.replace_update_raw(
            &format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
            "Human <human@example.invalid> 1700000000 +0000",
            &parents,
        );
    });
    refusal!("duplicate local update author", |f: &mut UpdateFixture| {
        let parents = f.update_parents();
        f.replace_update_raw(
            &format!(
                "{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000\nauthor Human <human@example.invalid> 1700000000 +0000"
            ),
            "GitHub <noreply@github.com> 1700000000 +0000",
            &parents,
        );
    });
    refusal!("reversed local update parents", |f: &mut UpdateFixture| {
        let parents = [f.base.clone(), f.prior_head.clone()];
        f.replace_update_raw(
            &format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
            "GitHub <noreply@github.com> 1700000000 +0000",
            &parents,
        );
    });
    refusal!("remote update SHA", |f: &mut UpdateFixture| {
        let other = f.prior_head.clone();
        f.update_remote()["sha"] = json!(other);
    });
    refusal!("remote update author account", |f: &mut UpdateFixture| {
        f.update_remote()["author"]["login"] = json!("other[bot]");
    });
    refusal!("remote update author identity", |f: &mut UpdateFixture| {
        f.update_remote()["commit"]["author"]["email"] = json!("forged@example.invalid");
    });
    refusal!(
        "remote update committer account",
        |f: &mut UpdateFixture| {
            f.update_remote()["committer"]["login"] = json!("other[bot]");
        }
    );
    refusal!(
        "remote update committer identity",
        |f: &mut UpdateFixture| {
            f.update_remote()["commit"]["committer"]["email"] = json!("forged@example.invalid");
        }
    );
    refusal!("remote update signature", |f: &mut UpdateFixture| {
        f.update_remote()["commit"]["verification"]["verified"] = json!(false);
    });
    refusal!("remote update signature reason", |f: &mut UpdateFixture| {
        f.update_remote()["commit"]["verification"]["reason"] = json!("invalid");
    });
    refusal!("remote update parent order", |f: &mut UpdateFixture| {
        f.update_remote()["parents"]
            .as_array_mut()
            .unwrap()
            .swap(0, 1);
    });
    refusal!("remote update tree", |f: &mut UpdateFixture| {
        f.update_remote()["commit"]["tree"]["sha"] =
            json!("1111111111111111111111111111111111111111");
    });
}

#[test]
fn update_branch_associations_are_complete_unique_and_exhaustive() {
    let mut missing = UpdateFixture::new();
    missing.update_pulls().as_array_mut().unwrap().clear();
    missing.assert_refused("missing update association");

    let mut malformed = UpdateFixture::new();
    malformed
        .update_pulls()
        .as_array_mut()
        .unwrap()
        .push(Value::Null);
    malformed.assert_refused("malformed update association");

    let mut ambiguous = UpdateFixture::new();
    let mut duplicate = ambiguous.update_pulls()[0].clone();
    duplicate["number"] = json!(405);
    ambiguous
        .update_pulls()
        .as_array_mut()
        .unwrap()
        .push(duplicate);
    ambiguous.assert_refused("multiple completed update associations");

    let mut terminal_failure = UpdateFixture::new();
    let mut claimed_terminal = terminal_failure.update_pulls()[0].clone();
    claimed_terminal["number"] = json!(405);
    claimed_terminal["merge_commit_sha"] = json!(terminal_failure.update.clone());
    terminal_failure
        .update_pulls()
        .as_array_mut()
        .unwrap()
        .push(claimed_terminal);
    terminal_failure.assert_refused("failed terminal proof reinterpreted as update");

    let mut paginated = UpdateFixture::new();
    let path = format!(
        "{ROOT}/commits/{}/pulls?per_page=100&page=1",
        paginated.update
    );
    let real = paginated.api.responses[&path][0].clone();
    let mut first = vec![real.clone()];
    first.extend((2..=100).map(|number| json!({"number":number,"merge_commit_sha":null})));
    paginated.api.responses.insert(path, json!(first));
    paginated.api.responses.insert(
        format!(
            "{ROOT}/commits/{}/pulls?per_page=100&page=2",
            paginated.update
        ),
        json!([real]),
    );
    paginated.assert_refused("later-page duplicate update association");
}

#[test]
fn update_branch_pull_request_summary_and_detail_are_bound() {
    macro_rules! refusal {
        ($label:literal, $change:expr) => {{
            let mut fixture = UpdateFixture::new();
            ($change)(&mut fixture);
            fixture.assert_refused($label);
        }};
    }

    refusal!("summary number", |f: &mut UpdateFixture| {
        f.update_pulls()[0]["number"] = json!(405);
    });
    refusal!("summary repository name", |f: &mut UpdateFixture| {
        f.update_pulls()[0]["head"]["repo"]["full_name"] = json!("elsewhere/repository");
    });
    refusal!("summary repository id", |f: &mut UpdateFixture| {
        f.update_pulls()[0]["base"]["repo"]["id"] = json!(124);
    });
    refusal!("summary head", |f: &mut UpdateFixture| {
        let other = f.prior_head.clone();
        f.update_pulls()[0]["head"]["sha"] = json!(other);
    });
    refusal!("summary base", |f: &mut UpdateFixture| {
        f.update_pulls()[0]["base"]["ref"] = json!("topic");
    });
    refusal!("detail number", |f: &mut UpdateFixture| {
        f.pr()["number"] = json!(405);
    });
    refusal!("detail merge identity", |f: &mut UpdateFixture| {
        let other = f.update.clone();
        f.pr()["merge_commit_sha"] = json!(other);
    });
    refusal!("detail actor", |f: &mut UpdateFixture| {
        f.pr()["merged_by"]["login"] = json!("other[bot]");
    });
    refusal!("detail open state", |f: &mut UpdateFixture| {
        f.pr()["state"] = json!("open");
    });
    refusal!("detail unmerged state", |f: &mut UpdateFixture| {
        f.pr()["merged"] = json!(false);
    });
    refusal!("detail fork", |f: &mut UpdateFixture| {
        f.pr()["head"]["repo"]["full_name"] = json!("elsewhere/repository");
    });
    refusal!("detail repository id", |f: &mut UpdateFixture| {
        f.pr()["base"]["repo"]["id"] = json!(124);
    });
    refusal!("detail nondefault base", |f: &mut UpdateFixture| {
        f.pr()["base"]["ref"] = json!("topic");
    });
    refusal!("detail accepted head", |f: &mut UpdateFixture| {
        let other = f.prior_head.clone();
        f.pr()["head"]["sha"] = json!(other);
    });
}

#[test]
fn final_merge_is_exactly_authenticated_and_bound_to_the_same_pull_request() {
    macro_rules! refusal {
        ($label:literal, $change:expr) => {{
            let mut fixture = UpdateFixture::new();
            ($change)(&mut fixture);
            fixture.assert_refused($label);
        }};
    }

    refusal!("local final merge author", |f: &mut UpdateFixture| {
        let parents = f.merge_parents();
        let tree = f.tree.clone();
        f.replace_final_raw(
            &tree,
            &parents,
            "Human <human@example.invalid> 1700000000 +0000",
            "GitHub <noreply@github.com> 1700000000 +0000",
        );
    });
    refusal!("local final merge committer", |f: &mut UpdateFixture| {
        let parents = f.merge_parents();
        let tree = f.tree.clone();
        f.replace_final_raw(
            &tree,
            &parents,
            &format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
            "Human <human@example.invalid> 1700000000 +0000",
        );
    });
    refusal!("remote final merge SHA", |f: &mut UpdateFixture| {
        let other = f.update.clone();
        f.merge_remote()["sha"] = json!(other);
    });
    refusal!("remote final merge author", |f: &mut UpdateFixture| {
        f.merge_remote()["author"]["login"] = json!("other[bot]");
    });
    refusal!("remote final merge committer", |f: &mut UpdateFixture| {
        f.merge_remote()["committer"]["login"] = json!("other[bot]");
    });
    refusal!("remote final merge signature", |f: &mut UpdateFixture| {
        f.merge_remote()["commit"]["verification"]["verified"] = json!(false);
    });
    refusal!(
        "remote final merge parent order",
        |f: &mut UpdateFixture| {
            f.merge_remote()["parents"]
                .as_array_mut()
                .unwrap()
                .swap(0, 1);
        }
    );
    refusal!("remote final merge tree", |f: &mut UpdateFixture| {
        f.merge_remote()["commit"]["tree"]["sha"] =
            json!("1111111111111111111111111111111111111111");
    });
    refusal!(
        "missing final merge association",
        |f: &mut UpdateFixture| {
            f.merge_pulls().as_array_mut().unwrap().clear();
        }
    );
    refusal!(
        "ambiguous final merge association",
        |f: &mut UpdateFixture| {
            let mut duplicate = f.merge_pulls()[0].clone();
            duplicate["number"] = json!(405);
            f.merge_pulls().as_array_mut().unwrap().push(duplicate);
        }
    );
    refusal!(
        "different completed final association",
        |f: &mut UpdateFixture| {
            let mut different = f.merge_pulls()[0].clone();
            different["number"] = json!(405);
            different["merge_commit_sha"] = json!("1111111111111111111111111111111111111111");
            f.merge_pulls().as_array_mut().unwrap().push(different);
        }
    );
    refusal!("final merge tied to another PR", |f: &mut UpdateFixture| {
        f.merge_pulls()[0]["number"] = json!(405);
    });
    refusal!("final merge summary repository", |f: &mut UpdateFixture| {
        f.merge_pulls()[0]["base"]["repo"]["full_name"] = json!("elsewhere/repository");
    });
    refusal!("final merge summary head", |f: &mut UpdateFixture| {
        let other = f.prior_head.clone();
        f.merge_pulls()[0]["head"]["sha"] = json!(other);
    });
    refusal!("final merge summary base", |f: &mut UpdateFixture| {
        f.merge_pulls()[0]["base"]["ref"] = json!("topic");
    });
    refusal!("unpublished final merge", |f: &mut UpdateFixture| {
        f.api.responses.get_mut(REF).unwrap()["object"]["sha"] = json!(f.update);
    });

    let mut changed_tree = UpdateFixture::new();
    let blob = git(
        changed_tree.dir.path(),
        &["hash-object", "-w", "--stdin"],
        b"changed final tree\n",
    );
    let tree = git(
        changed_tree.dir.path(),
        &["mktree"],
        format!("100644 blob {blob}\tchanged\n").as_bytes(),
    );
    let parents = changed_tree.merge_parents();
    changed_tree.replace_final(&tree, &parents);
    changed_tree.assert_refused("final merge tree differs from accepted head");
}

#[test]
fn missing_local_update_graph_objects_refuse() {
    for object in ["prior", "base", "update", "merge", "tree"] {
        let fixture = UpdateFixture::new();
        let oid = match object {
            "prior" => &fixture.prior_head,
            "base" => &fixture.base,
            "update" => &fixture.update,
            "merge" => &fixture.merge,
            "tree" => &fixture.tree,
            _ => unreachable!(),
        };
        std::fs::remove_file(
            fixture
                .dir
                .path()
                .join(".git/objects")
                .join(&oid[..2])
                .join(&oid[2..]),
        )
        .unwrap();
        fixture.assert_refused(&format!("missing local {object} object"));
    }
}

#[test]
fn unsupported_update_branch_shapes_refuse() {
    let mut direct_after_update = UpdateFixture::new();
    let direct = commit(
        direct_after_update.dir.path(),
        &direct_after_update.tree,
        &[&direct_after_update.update],
        false,
        "direct head after update",
    );
    let parents = [direct_after_update.base.clone(), direct.clone()];
    direct_after_update.replace_final_with_head(
        &direct_after_update.tree.clone(),
        &parents,
        &direct,
    );
    direct_after_update.assert_refused("direct head commit after update");

    let mut multiple_updates = UpdateFixture::new();
    let advanced_base = commit(
        multiple_updates.dir.path(),
        &multiple_updates.tree,
        &[&multiple_updates.base],
        false,
        "base advances again",
    );
    let second_update = commit(
        multiple_updates.dir.path(),
        &multiple_updates.tree,
        &[&multiple_updates.update, &advanced_base],
        true,
        "second update",
    );
    let final_parents = [advanced_base.clone(), second_update.clone()];
    multiple_updates.replace_final_with_head(
        &multiple_updates.tree.clone(),
        &final_parents,
        &second_update,
    );
    multiple_updates.prove_commit(
        second_update.clone(),
        &[multiple_updates.update.clone(), advanced_base],
        multiple_updates.tree.clone(),
    );
    let pull = multiple_updates.pull_with_head(&second_update);
    multiple_updates.api.responses.insert(
        format!("{ROOT}/commits/{second_update}/pulls?per_page=100&page=1"),
        json!([pull]),
    );
    multiple_updates.assert_refused("multiple branch updates");

    let mut squash = UpdateFixture::new();
    squash.replace_final(&squash.tree.clone(), &[squash.base.clone()]);
    squash.assert_refused("squash final merge");

    let mut rebase = UpdateFixture::new();
    rebase.replace_final(&rebase.tree.clone(), &[rebase.update.clone()]);
    rebase.assert_refused("rebase-shaped final merge");

    let mut advanced_final_base = UpdateFixture::new();
    let advanced = commit(
        advanced_final_base.dir.path(),
        &advanced_final_base.tree,
        &[&advanced_final_base.base],
        false,
        "advanced final base",
    );
    advanced_final_base.replace_final(
        &advanced_final_base.tree.clone(),
        &[advanced, advanced_final_base.update.clone()],
    );
    advanced_final_base.assert_refused("advanced final base");
}

#[test]
fn published_bot_merge_allows_a_new_exact_bot_descendant() {
    let f = Fixture::new();
    assert!(
        f.verify().is_ok(),
        "authenticated historical merge must be admitted: {:?}",
        f.verify()
    );
}

macro_rules! refusal {
    ($name:ident, $change:expr) => {
        #[test]
        fn $name() {
            let mut f = Fixture::new();
            $change(&mut f);
            assert!(
                f.verify().is_err(),
                "invalid evidence admitted by both delivery paths"
            );
        }
    };
}

refusal!(wrong_repository_id, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(ROOT)
    .unwrap()["id"] =
    json!(124));
refusal!(wrong_repository_name, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(ROOT)
    .unwrap()["full_name"] =
    json!("elsewhere/repository"));
refusal!(nonpublic_repository, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(ROOT)
    .unwrap()["visibility"] =
    json!("private"));
refusal!(contradictory_private_repository, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(ROOT)
    .unwrap()["private"] =
    json!(true));
refusal!(missing_repository_identity, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(ROOT)
    .unwrap()["id"] =
    Value::Null);
refusal!(missing_default_branch, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(ROOT)
    .unwrap()["default_branch"] =
    Value::Null);
refusal!(missing_authority, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(&format!(
        "{ROOT}/rulesets?includes_parents=true&per_page=100&page=1"
    ))
    .unwrap()
    .as_array_mut()
    .unwrap()
    .clear());
refusal!(ambiguous_authority, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(&format!(
        "{ROOT}/rulesets?includes_parents=true&per_page=100&page=1"
    ))
    .unwrap()
    .as_array_mut()
    .unwrap()
    .push(json!({"id":8,"name":"b10x-bot-branch-authority"})));
refusal!(wrong_authority_identity, |f: &mut Fixture| f.authority()
    ["id"] =
    json!(8));
refusal!(
    redacted_authority,
    |f: &mut Fixture| f.authority()["bypass_actors"] = Value::Null
);
refusal!(wrong_app, |f: &mut Fixture| f.authority()["bypass_actors"]
    [0]["actor_id"] =
    json!(4579526));
refusal!(widened_authority, |f: &mut Fixture| {
    f.authority()["bypass_actors"]
        .as_array_mut()
        .unwrap()
        .push(json!({"actor_id":1,"actor_type":"RepositoryRole","bypass_mode":"always"}))
});
refusal!(
    disabled_authority,
    |f: &mut Fixture| f.authority()["enforcement"] = json!("disabled")
);
refusal!(authority_excludes_branch, |f: &mut Fixture| f.authority()
    ["conditions"]["ref_name"]["exclude"] =
    json!(["refs/heads/topic"]));
refusal!(authority_only_default_branch, |f: &mut Fixture| f
    .authority()["conditions"]["ref_name"]["include"] =
    json!(["~DEFAULT_BRANCH"]));
refusal!(authority_missing_update_rule, |f: &mut Fixture| {
    f.authority()["rules"].as_array_mut().unwrap().remove(1);
});
refusal!(wrong_default_ref, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(REF)
    .unwrap()["ref"] =
    json!("refs/heads/topic"));
refusal!(default_ref_not_commit, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(REF)
    .unwrap()["object"]["type"] =
    json!("tag"));
refusal!(
    unpublished_merge_despite_forged_local_remote_ref,
    |f: &mut Fixture| {
        git(
            f.dir.path(),
            &["update-ref", "refs/remotes/origin/main", &f.merge],
            b"",
        );
        f.api.responses.get_mut(REF).unwrap()["object"]["sha"] = json!(f.baseline);
    }
);
refusal!(missing_published_object, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(REF)
    .unwrap()["object"]["sha"] =
    json!("1111111111111111111111111111111111111111"));
refusal!(wrong_remote_merge_sha, |f: &mut Fixture| {
    let other = f.topic.clone();
    f.remote_commit()["sha"] = json!(other);
});
refusal!(wrong_remote_author_account, |f: &mut Fixture| f
    .remote_commit()["author"]["login"] =
    json!("other[bot]"));
refusal!(wrong_remote_author_identity, |f: &mut Fixture| f
    .remote_commit()["commit"]["author"]["email"] =
    json!("forged@example.invalid"));
refusal!(wrong_remote_committer_account, |f: &mut Fixture| f
    .remote_commit()["committer"]["login"] =
    json!("other[bot]"));
refusal!(wrong_remote_committer_identity, |f: &mut Fixture| f
    .remote_commit()["commit"]["committer"]["email"] =
    json!("forged@example.invalid"));
refusal!(unverified_signature, |f: &mut Fixture| f.remote_commit()
    ["commit"]["verification"]["verified"] =
    json!(false));
refusal!(invalid_signature_reason, |f: &mut Fixture| f
    .remote_commit()["commit"]["verification"]["reason"] =
    json!("invalid"));
refusal!(
    redacted_signature,
    |f: &mut Fixture| f.remote_commit()["commit"]["verification"] = Value::Null
);
refusal!(wrong_remote_first_parent, |f: &mut Fixture| {
    let other = f.topic.clone();
    f.remote_commit()["parents"][0]["sha"] = json!(other);
});
refusal!(wrong_remote_second_parent, |f: &mut Fixture| {
    let other = f.baseline.clone();
    f.remote_commit()["parents"][1]["sha"] = json!(other);
});
refusal!(
    wrong_remote_tree,
    |f: &mut Fixture| f.remote_commit()["commit"]["tree"]["sha"] =
        json!("1111111111111111111111111111111111111111")
);
refusal!(missing_associated_pr, |f: &mut Fixture| f
    .api
    .responses
    .get_mut(&format!(
        "{ROOT}/commits/{}/pulls?per_page=100&page=1",
        f.merge
    ))
    .unwrap()
    .as_array_mut()
    .unwrap()
    .clear());
refusal!(ambiguous_associated_pr, |f: &mut Fixture| {
    let list = f
        .api
        .responses
        .get_mut(&format!(
            "{ROOT}/commits/{}/pulls?per_page=100&page=1",
            f.merge
        ))
        .unwrap()
        .as_array_mut()
        .unwrap();
    let mut duplicate = list[0].clone();
    duplicate["number"] = json!(2);
    list.push(duplicate);
});
refusal!(wrong_pr_number, |f: &mut Fixture| f.pr()["number"] =
    json!(2));
refusal!(unmerged_pr, |f: &mut Fixture| f.pr()["merged"] =
    json!(false));
refusal!(open_pr, |f: &mut Fixture| f.pr()["state"] = json!("open"));
refusal!(wrong_pr_merge, |f: &mut Fixture| {
    let other = f.topic.clone();
    f.pr()["merge_commit_sha"] = json!(other);
});
refusal!(wrong_pr_merge_actor, |f: &mut Fixture| f.pr()["merged_by"]
    ["login"] =
    json!("other[bot]"));
refusal!(
    fork_pr,
    |f: &mut Fixture| f.pr()["head"]["repo"]["full_name"] = json!("elsewhere/repository")
);
refusal!(
    wrong_pr_head_repository_id,
    |f: &mut Fixture| f.pr()["head"]["repo"]["id"] = json!(124)
);
refusal!(wrong_pr_base_repository, |f: &mut Fixture| f.pr()["base"]
    ["repo"]["full_name"] =
    json!("elsewhere/repository"));
refusal!(
    wrong_pr_base_repository_id,
    |f: &mut Fixture| f.pr()["base"]["repo"]["id"] = json!(124)
);
refusal!(
    nondefault_pr_target,
    |f: &mut Fixture| f.pr()["base"]["ref"] = json!("topic")
);
refusal!(wrong_pr_head, |f: &mut Fixture| {
    let other = f.baseline.clone();
    f.pr()["head"]["sha"] = json!(other);
});
refusal!(api_unavailable, |f: &mut Fixture| f.api.responses.clear());

#[test]
fn every_remote_read_is_required_and_missing_fields_fail_closed() {
    let valid = Fixture::new();
    for path in valid.api.responses.keys() {
        let mut f = Fixture::new();
        f.api.responses.remove(path);
        assert!(f.verify().is_err(), "missing read admitted: {path}");
    }
    for (kind, fields) in [
        (
            "commit",
            vec![
                "/author/login",
                "/committer/login",
                "/commit/author/name",
                "/commit/author/email",
                "/commit/committer/name",
                "/commit/committer/email",
                "/sha",
                "/parents",
                "/commit/tree/sha",
            ],
        ),
        (
            "pr",
            vec![
                "/head/repo/id",
                "/base/repo/id",
                "/head/repo/full_name",
                "/base/repo/full_name",
                "/base/ref",
                "/head/sha",
                "/merged_by/login",
                "/number",
                "/state",
                "/merged",
                "/merge_commit_sha",
            ],
        ),
    ] {
        for field in fields {
            let mut f = Fixture::new();
            let value = if kind == "commit" {
                f.remote_commit()
            } else {
                f.pr()
            };
            *value.pointer_mut(field).unwrap() = Value::Null;
            assert!(f.verify().is_err(), "missing {kind} {field} admitted");
        }
    }
}

#[test]
fn direct_bot_delivery_needs_no_remote_exception() {
    let mut f = Fixture::new();
    f.candidate = f.topic.clone();
    f.api.responses.clear();
    f.verify().unwrap();
    assert_eq!(f.api.calls.get(), 0);
}

#[test]
fn nested_historical_merges_each_require_their_own_proof() {
    let mut f = Fixture::new();
    let head = commit(f.dir.path(), &f.tree, &[&f.merge], false, "nested topic");
    let merge = commit(
        f.dir.path(),
        &f.tree,
        &[&f.merge, &head],
        true,
        "nested merge",
    );
    f.prove_merge(merge.clone(), f.merge.clone(), head, 2);
    f.candidate = merge.clone();
    f.api.responses.get_mut(REF).unwrap()["object"]["sha"] = json!(merge);
    f.verify().unwrap();
    f.api
        .responses
        .remove(&format!("{ROOT}/commits/{}", f.merge));
    assert!(f.verify().is_err(), "outer merge cannot attest inner merge");
}

#[test]
fn local_merge_tree_must_equal_pr_head_tree() {
    let mut f = Fixture::new();
    let blob = git(
        f.dir.path(),
        &["hash-object", "-w", "--stdin"],
        b"changed candidate\n",
    );
    let tree = git(
        f.dir.path(),
        &["mktree"],
        format!("100644 blob {blob}\tchanged\n").as_bytes(),
    );
    let parents = [f.baseline.clone(), f.topic.clone()];
    f.replace_merge(&tree, &[&parents[0], &parents[1]]);
    assert!(
        f.verify().is_err(),
        "remote attestation cannot bless a changed PR tree"
    );
}

/// A stale PR basis is refused when the merge dropped content the base carried.
///
/// The base advanced past the fork point with a new file, and the merge adopted the head's tree,
/// so the base's file is gone from the merge. Git's own merge of the two parents keeps it, so the
/// recorded tree is not that merge.
#[test]
fn merge_basis_must_already_be_in_pr_head() {
    let mut f = Fixture::new();
    let blob = git(
        f.dir.path(),
        &["hash-object", "-w", "--stdin"],
        b"content only the default branch carried\n",
    );
    let base_tree = git(
        f.dir.path(),
        &["mktree"],
        format!("100644 blob {blob}\tbase-only\n").as_bytes(),
    );
    let advanced = commit(
        f.dir.path(),
        &base_tree,
        &[&f.baseline],
        false,
        "advanced default branch",
    );
    let tree = f.tree.clone();
    let topic = f.topic.clone();
    f.replace_merge(&tree, &[&advanced, &topic]);
    let error = f
        .verify()
        .expect_err("a merge that dropped the base's content is refused");
    assert!(
        error.to_string().contains("is not the local merge"),
        "refused for the dropped base content, not for another reason: {error:#}"
    );
}

/// A stale PR basis whose base added nothing since the fork point is admitted.
///
/// The base advanced by commits that leave its tree equal to the fork point's, so the merge, which
/// adopts the head's tree, dropped nothing. Refusing this shape left a repository whose default
/// branch took one such merge unable to deliver again (epistemic-knowledge-runtime PR #12).
#[test]
fn a_stale_basis_that_added_nothing_is_admitted() {
    let mut f = Fixture::new();
    let advanced = commit(
        f.dir.path(),
        &f.tree,
        &[&f.baseline],
        false,
        "advanced default branch, tree unchanged",
    );
    let tree = f.tree.clone();
    let topic = f.topic.clone();
    f.replace_merge(&tree, &[&advanced, &topic]);
    assert!(
        f.verify().is_ok(),
        "a base that added nothing since the fork cannot have been dropped: {:?}",
        f.verify()
    );
}

#[test]
fn github_committer_exception_requires_one_or_two_parents() {
    // One parent is a squash merge and two is an ordinary merge; both are shapes the button
    // produces. A root commit and an octopus are neither, and stay refused on shape alone —
    // before any remote claim is fetched, which is what makes this a cheap guard.
    for count in [0, 3] {
        let mut f = Fixture::new();
        let tree = f.tree.clone();
        let third = commit(f.dir.path(), &tree, &[&f.baseline], false, "third parent");
        let parents = [f.baseline.clone(), f.topic.clone(), third];
        f.replace_merge(
            &tree,
            &parents[..count]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        if count == 3 {
            // All other claims remain valid: only the third local parent is bad.
            f.prove_merge(f.merge.clone(), parents[0].clone(), parents[1].clone(), 1);
        }
        let error = f.verify().expect_err("GitHub merge has wrong parent count");
        if count > 0 {
            assert!(
                error.to_string().contains("one or two parents"),
                "wrong refusal: {error:#}"
            );
        }
    }
}

#[test]
fn a_squash_merge_is_admitted_on_shape_and_still_proved_against_the_remote() {
    // The shape check must let a one-parent GitHub commit through, and everything after it must
    // still run: this asserts the refusal comes from the remote proof, never from the parent
    // count. Without the first half a repository whose default branch has taken one squash merge
    // can never deliver again; without the second half the squash would be admitted unproved.
    let mut f = Fixture::new();
    let tree = f.tree.clone();
    let baseline = f.baseline.clone();
    f.replace_merge(&tree, &[baseline.as_str()]);
    let error = f
        .verify()
        .expect_err("a squash merge is still proved against the remote");
    assert!(
        !error.to_string().contains("one or two parents"),
        "the shape check refused a squash merge: {error:#}"
    );
}

#[test]
fn strict_direct_identity_applies_to_side_branch_ancestors() {
    let mut f = Fixture::new();
    let raw = format!(
        "tree {}\nparent {}\nauthor Human <human@example.invalid> 1700000000 +0000\ncommitter {BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000\n\nside ancestor\n",
        f.tree, f.baseline
    );
    let side = git(
        f.dir.path(),
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        raw.as_bytes(),
    );
    let join = commit(
        f.dir.path(),
        &f.tree,
        &[&f.topic, &side],
        false,
        "joined side branch",
    );
    let tree = f.tree.clone();
    let baseline = f.baseline.clone();
    f.replace_merge(&tree, &[&baseline, &join]);
    assert!(
        f.verify().is_err(),
        "valid PR proof cannot exempt a bad side ancestor"
    );
}

#[test]
fn direct_identity_rejects_duplicates_spoofs_and_malformed_dates() {
    let f = Fixture::new();
    for (author, committer) in [
        (
            format!(
                "{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000\nauthor Human <human@example.invalid> 1700000000 +0000"
            ),
            format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
        ),
        (
            format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
            format!(
                "{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000\ncommitter Human <human@example.invalid> 1700000000 +0000"
            ),
        ),
        (
            format!("{BOT_NAME} <{BOT_EMAIL}> invalid +0000"),
            format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
        ),
        (
            format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
            format!("{BOT_NAME} <{BOT_EMAIL}> invalid +0000"),
        ),
        (
            format!("{BOT_NAME} <forged@example.invalid> 1700000000 +0000"),
            format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
        ),
    ] {
        let raw = format!(
            "tree {}\nparent {}\nauthor {author}\ncommitter {committer}\n\nidentity fixture\n",
            f.tree, f.baseline
        );
        let id = git(
            f.dir.path(),
            &[
                "hash-object",
                "--literally",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ],
            raw.as_bytes(),
        );
        assert!(
            Git::new(f.dir.path())
                .unwrap()
                .verify_bot(std::slice::from_ref(&id))
                .is_err()
        );
        assert!(
            b10x_gates::delivery::verify_publication(
                &Git::new(f.dir.path()).unwrap(),
                &f.policy,
                REPOSITORY,
                &id,
                &f.api
            )
            .is_err()
        );
    }
}

#[test]
fn production_entrypoints_bind_shared_guard_before_delivery_and_receipt_reuse() {
    let root = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let main = std::fs::read_to_string(root.join("src/main.rs")).unwrap();
    let publish = main
        .split("if let Action::Publish { remote_ref, .. }")
        .nth(1)
        .unwrap();
    assert!(
        publish.find("delivery::verify_publication(").unwrap()
            < publish.find("github.git(").unwrap()
    );
    let hooks = std::fs::read_to_string(root.join("src/hooks.rs")).unwrap();
    let push = hooks
        .split("let candidate = git.candidate(")
        .nth(1)
        .unwrap();
    assert!(push.find("verify_pre_push(").unwrap() < push.find("let retained =").unwrap());
}

#[test]
fn merge_raw_identity_cannot_be_overridden_by_remote_claims() {
    for (author, committer) in [
        (
            "Human <human@example.invalid> 1700000000 +0000".to_owned(),
            "GitHub <noreply@github.com> 1700000000 +0000",
        ),
        (
            format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
            "GitHub <forged@example.invalid> 1700000000 +0000",
        ),
        (
            format!(
                "{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000\nauthor Human <human@example.invalid> 1700000000 +0000"
            ),
            "GitHub <noreply@github.com> 1700000000 +0000",
        ),
        (
            format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000"),
            "GitHub <noreply@github.com> 1700000000 +0000\ncommitter Human <human@example.invalid> 1700000000 +0000",
        ),
    ] {
        let mut f = Fixture::new();
        let raw = format!(
            "tree {}\nparent {}\nparent {}\nauthor {author}\ncommitter {committer}\n\nclaimed merge\n",
            f.tree, f.baseline, f.topic
        );
        f.merge = git(
            f.dir.path(),
            &[
                "hash-object",
                "--literally",
                "-t",
                "commit",
                "-w",
                "--stdin",
            ],
            raw.as_bytes(),
        );
        f.candidate = f.merge.clone();
        f.api.responses.get_mut(REF).unwrap()["object"]["sha"] = json!(f.merge);
        f.prove_merge(f.merge.clone(), f.baseline.clone(), f.topic.clone(), 1);
        assert!(
            f.verify().is_err(),
            "API claims cannot override raw identity"
        );
    }
}

#[test]
fn missing_local_parent_and_tree_objects_refuse() {
    for parent in [true, false] {
        let mut f = Fixture::new();
        if !parent {
            // Git can synthesize the empty tree without a loose object.
            let blob = git(
                f.dir.path(),
                &["hash-object", "-w", "--stdin"],
                b"retained tree\n",
            );
            let tree = git(
                f.dir.path(),
                &["mktree"],
                format!("100644 blob {blob}\tfile\n").as_bytes(),
            );
            let head = commit(f.dir.path(), &tree, &[&f.baseline], false, "nonempty head");
            let baseline = f.baseline.clone();
            f.replace_merge(&tree, &[&baseline, &head]);
            f.verify().unwrap();
        }
        let id = if parent { &f.topic } else { &f.tree };
        std::fs::remove_file(
            f.dir
                .path()
                .join(".git/objects")
                .join(&id[..2])
                .join(&id[2..]),
        )
        .unwrap();
        assert!(f.verify().is_err(), "missing local object admitted");
    }
}

#[test]
fn head_outside_enrolled_history_refuses_even_with_exact_bot_identity() {
    let mut f = Fixture::new();
    f.candidate = commit(f.dir.path(), &f.tree, &[], false, "unrelated root");
    assert!(f.verify().is_err());
}

#[test]
fn paginated_evidence_is_exhausted_before_admission() {
    for rulesets in [true, false] {
        let mut f = Fixture::new();
        let prefix = if rulesets {
            format!("{ROOT}/rulesets?includes_parents=true&")
        } else {
            format!("{ROOT}/commits/{}/pulls?", f.merge)
        };
        let first = format!("{prefix}per_page=100&page=1");
        let real = f.api.responses.remove(&first).unwrap();
        let fillers: Vec<_> = (0..100).map(|n| json!({"id":1000+n,"name":"unrelated","number":1000+n,"merge_commit_sha":"1111111111111111111111111111111111111111"})).collect();
        f.api.responses.insert(first, json!(fillers));
        f.api
            .responses
            .insert(format!("{prefix}per_page=100&page=2"), real);
        f.verify().unwrap();
        f.api
            .responses
            .remove(&format!("{prefix}per_page=100&page=2"));
        assert!(
            f.verify().is_err(),
            "unavailable later page cannot be ignored"
        );
    }
}

#[test]
fn pagination_limit_redaction_and_oversized_pages_fail_closed() {
    for rulesets in [true, false] {
        for shape in ["redacted", "oversized", "limit"] {
            let mut f = Fixture::new();
            let prefix = if rulesets {
                format!("{ROOT}/rulesets?includes_parents=true&")
            } else {
                format!("{ROOT}/commits/{}/pulls?", f.merge)
            };
            let first = format!("{prefix}per_page=100&page=1");
            let real = f.api.responses.get(&first).unwrap()[0].clone();
            if shape == "redacted" {
                f.api.responses.insert(first, Value::Null);
            } else {
                let count = if shape == "oversized" { 101 } else { 100 };
                let mut values = vec![
                    json!({"id":9000,"name":"unrelated","merge_commit_sha":"1111111111111111111111111111111111111111"});
                    count
                ];
                values[0] = real;
                f.api.responses.insert(first, json!(values));
                if shape == "limit" {
                    for page in 2..=20 {
                        f.api.responses.insert(format!("{prefix}per_page=100&page={page}"), json!(vec![json!({"id":9000,"name":"unrelated","merge_commit_sha":"1111111111111111111111111111111111111111"}); 100]));
                    }
                }
            }
            assert!(f.verify().is_err(), "ambiguous {shape} pagination admitted");
        }
    }
}

#[test]
fn branch_with_slash_is_encoded_as_api_path_data() {
    let mut f = Fixture::new();
    f.api.responses.get_mut(ROOT).unwrap()["default_branch"] = json!("releases/main");
    let mut reference = f.api.responses.remove(REF).unwrap();
    reference["ref"] = json!("refs/heads/releases/main");
    f.api
        .responses
        .insert(format!("{ROOT}/git/ref/heads/releases%2Fmain"), reference);
    f.pr()["base"]["ref"] = json!("releases/main");
    f.verify().unwrap();
}

const BOT_USER_ID: u64 = 316_511_680;

fn bot_account() -> Value {
    json!({"login":BOT_NAME,"type":"Bot","id":BOT_USER_ID})
}

/// Turn public evidence into what GitHub returns for a private repository on a plan without
/// rulesets: the repository says private, the ruleset endpoints do not answer, and every
/// pull-request record carries the full account objects GitHub always returns.
fn privatize(responses: &mut BTreeMap<String, Value>) {
    let root = responses.get_mut(ROOT).unwrap();
    root["private"] = json!(true);
    root["visibility"] = json!("private");
    responses.retain(|path, _| !path.contains("/rulesets"));
    for (path, value) in responses.iter_mut() {
        if !path.contains("/pulls") {
            continue;
        }
        let records: Vec<&mut Value> = match value {
            Value::Array(list) => list.iter_mut().collect(),
            other => vec![other],
        };
        for record in records {
            record["merged_by"] = bot_account();
            record["user"] = bot_account();
        }
    }
}

impl Fixture {
    fn private() -> Self {
        let mut f = Self::new();
        privatize(&mut f.api.responses);
        f
    }
}

#[test]
fn private_repository_admits_the_bot_merge_of_a_bot_head_without_rulesets() {
    let f = Fixture::private();
    assert!(
        f.api
            .responses
            .keys()
            .all(|path| !path.contains("rulesets")),
        "fixture must not offer the ruleset a private repository cannot have"
    );
    assert!(
        f.verify().is_ok(),
        "the App's merge of a bot head on a private repository must be admitted: {:?}",
        f.verify()
    );
}

#[test]
fn private_repository_admits_an_exact_update_branch_then_final_merge() {
    let mut f = UpdateFixture::new();
    privatize(&mut f.api.responses);
    for (entrypoint, result) in ["verify_publication", "verify_pre_push"]
        .into_iter()
        .zip(f.verify())
    {
        assert!(result.is_ok(), "{entrypoint} refused: {result:?}");
    }
    f.pr()["user"]["login"] = json!("someone");
    f.assert_refused("private update merge opened by a person");
}

#[test]
fn public_repository_still_requires_its_branch_authority() {
    // The private proof must never become a fallback for a public repository whose ruleset is
    // missing: the authenticated visibility selects the proof, not the evidence that happens to
    // answer.
    let mut f = Fixture::new();
    f.api
        .responses
        .retain(|path, _| !path.contains("/rulesets"));
    for (path, value) in f.api.responses.iter_mut() {
        if path.contains("/pulls/") {
            value["merged_by"] = bot_account();
            value["user"] = bot_account();
        }
    }
    assert!(
        f.verify().is_err(),
        "public repository admitted without rulesets"
    );
}

macro_rules! private_refusal {
    ($name:ident, $needle:expr, $change:expr) => {
        #[test]
        fn $name() {
            let mut f = Fixture::private();
            f.verify()
                .expect("the unchanged private fixture is admitted");
            $change(&mut f);
            let error = f
                .verify()
                .expect_err("invalid private evidence admitted by both delivery paths");
            assert!(
                format!("{error:#}").contains($needle),
                "refused for another reason: {error:#}"
            );
        }
    };
}

private_refusal!(
    private_merge_by_a_person_refuses,
    "merged by the exact bot",
    |f: &mut Fixture| f.pr()["merged_by"] = json!({"login":"someone","type":"User","id":1})
);
private_refusal!(
    private_merge_by_a_user_account_named_like_the_bot_refuses,
    "merged by the exact bot account",
    |f: &mut Fixture| f.pr()["merged_by"]["type"] = json!("User")
);
private_refusal!(
    private_merge_by_another_account_id_refuses,
    "merged by the exact bot account",
    |f: &mut Fixture| f.pr()["merged_by"]["id"] = json!(BOT_USER_ID + 1)
);
private_refusal!(
    private_merge_without_account_id_refuses,
    "merged by the exact bot account",
    |f: &mut Fixture| f.pr()["merged_by"]["id"] = Value::Null
);
private_refusal!(
    private_pull_request_opened_by_a_person_refuses,
    "opened by the exact bot account",
    |f: &mut Fixture| f.pr()["user"] = json!({"login":"someone","type":"User","id":1})
);
private_refusal!(
    private_pull_request_without_opener_refuses,
    "opened by the exact bot account",
    |f: &mut Fixture| f.pr()["user"] = Value::Null
);
private_refusal!(
    private_mismatched_merge_commit_sha_refuses,
    "not this completed merge",
    |f: &mut Fixture| {
        let other = f.topic.clone();
        f.pr()["merge_commit_sha"] = json!(other);
    }
);
private_refusal!(
    private_mismatched_head_sha_refuses,
    "head is not the second merge parent",
    |f: &mut Fixture| {
        let other = f.baseline.clone();
        f.pr()["head"]["sha"] = json!(other);
    }
);
private_refusal!(
    private_unverified_merge_signature_refuses,
    "signature is not verified",
    |f: &mut Fixture| f.remote_commit()["commit"]["verification"]["verified"] = json!(false)
);
private_refusal!(
    private_unpublished_merge_refuses,
    "not on the authenticated published default branch",
    |f: &mut Fixture| {
        let baseline = f.baseline.clone();
        f.api.responses.get_mut(REF).unwrap()["object"]["sha"] = json!(baseline);
    }
);
private_refusal!(
    private_flag_with_public_visibility_refuses,
    "visibility",
    |f: &mut Fixture| f.api.responses.get_mut(ROOT).unwrap()["visibility"] = json!("public")
);
private_refusal!(
    public_flag_with_private_visibility_refuses,
    "visibility",
    |f: &mut Fixture| f.api.responses.get_mut(ROOT).unwrap()["private"] = json!(false)
);
private_refusal!(
    internal_visibility_refuses,
    "visibility",
    |f: &mut Fixture| f.api.responses.get_mut(ROOT).unwrap()["visibility"] = json!("internal")
);
private_refusal!(
    missing_private_flag_refuses,
    "visibility",
    |f: &mut Fixture| f.api.responses.get_mut(ROOT).unwrap()["private"] = Value::Null
);

#[test]
fn private_head_with_a_forged_or_foreign_identity_refuses() {
    // The App's merge record never vouches for the head it accepted: every head commit after the
    // baseline is still walked and must carry the exact bot identity itself.
    let mut f = Fixture::private();
    let raw = format!(
        "tree {}\nparent {}\nauthor someone <someone@example.invalid> 1700000000 +0000\ncommitter {BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000\n\nforeign head\n",
        f.tree, f.baseline
    );
    let head = git(
        f.dir.path(),
        &["hash-object", "-t", "commit", "-w", "--stdin"],
        raw.as_bytes(),
    );
    let tree = f.tree.clone();
    let baseline = f.baseline.clone();
    f.replace_merge(&tree, &[&baseline, &head]);
    privatize(&mut f.api.responses);
    assert!(
        f.verify().is_err(),
        "foreign head admitted on a private repository"
    );
}

#[test]
fn private_squash_merge_refuses_because_its_head_is_not_walked() {
    // A squash merge keeps no parent link to the head it accepted, so the head commits are never
    // walked. On a public repository the branch authority proves only the App wrote them; a
    // private repository has nothing that can, so the shape is refused there.
    let mut f = Fixture::new();
    let tree = f.tree.clone();
    let baseline = f.baseline.clone();
    f.replace_merge(&tree, &[baseline.as_str()]);
    let merge = f.merge.clone();
    f.api.responses.insert(format!("{ROOT}/commits/{merge}"), json!({
        "sha":merge,"author":{"login":BOT_NAME},"committer":{"login":"web-flow"},
        "commit":{"author":{"name":BOT_NAME,"email":BOT_EMAIL},"committer":{"name":"GitHub","email":"noreply@github.com"},"tree":{"sha":tree},"verification":{"verified":true,"reason":"valid"}},
        "parents":[{"sha":baseline}]
    }));
    let pr = json!({"number":1,"state":"closed","merged":true,"merge_commit_sha":merge,"merged_by":{"login":BOT_NAME},"head":{"sha":f.topic,"repo":{"full_name":REPOSITORY,"id":123}},"base":{"ref":"main","sha":baseline,"repo":{"full_name":REPOSITORY,"id":123}}});
    f.api.responses.insert(
        format!("{ROOT}/commits/{merge}/pulls?per_page=100&page=1"),
        json!([pr.clone()]),
    );
    f.api.responses.insert(format!("{ROOT}/pulls/1"), pr);
    f.verify()
        .expect("the same squash merge is admitted on a public repository");
    privatize(&mut f.api.responses);
    let error = f.verify().expect_err("private squash merge admitted");
    assert!(
        format!("{error:#}").contains("only two-parent"),
        "refused for another reason: {error:#}"
    );
}

fn tree_of(root: &Path, files: &[(&str, &[u8])]) -> String {
    let mut listing = String::new();
    for (name, content) in files {
        let blob = git(root, &["hash-object", "-w", "--stdin"], content);
        listing.push_str(&format!("100644 blob {blob}\t{name}\n"));
    }
    git(root, &["mktree"], listing.as_bytes())
}

/// The tree `git merge-tree` writes for two commits, conflicted or not, with the fixture's own
/// worktree attributes in force.
fn written_merge_tree(root: &Path, first: &str, second: &str) -> (String, bool) {
    let output = Command::new("git")
        .args(["merge-tree", "--write-tree", "--no-messages", first, second])
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap();
    let clean = match output.status.code() {
        Some(0) => true,
        Some(1) => false,
        other => panic!("merge-tree failed: {other:?}"),
    };
    let stdout = String::from_utf8(output.stdout).unwrap();
    (stdout.lines().next().unwrap().to_owned(), clean)
}

/// The shape every pull request merged after another one has: the base took a GitHub merge of
/// pull request 2 after pull request 1's head was cut, so pull request 1's merge is a real merge
/// whose tree carries both sides and equals neither parent's.
struct MovedBase {
    base: String,
    head: String,
}

impl Fixture {
    /// Pull request 2 adds `landed` and is merged by GitHub; pull request 1's head, cut from the
    /// baseline before that, adds `head_file`.
    fn moved_base(&mut self, head_file: (&str, &[u8])) -> MovedBase {
        let root = self.dir.path().to_path_buf();
        let base_tree = tree_of(&root, &[("landed", b"pull request 2\n")]);
        let side = commit(
            &root,
            &base_tree,
            &[&self.baseline],
            false,
            "pull request 2",
        );
        let base = commit(
            &root,
            &base_tree,
            &[&self.baseline, &side],
            true,
            "merge pull request 2",
        );
        let head_tree = tree_of(&root, &[head_file]);
        let head = commit(
            &root,
            &head_tree,
            &[&self.baseline],
            false,
            "pull request 1",
        );
        // Pull request 2's merge is proved on its own terms, with its own tree.
        let tree = std::mem::replace(&mut self.tree, base_tree);
        self.prove_merge(base.clone(), self.baseline.clone(), side, 2);
        self.tree = tree;
        MovedBase { base, head }
    }

    /// GitHub merges pull request 1 onto the moved base and records `tree`.
    fn merge_moved_base(&mut self, moved: &MovedBase, tree: &str) {
        self.replace_merge(tree, &[&moved.base, &moved.head]);
    }
}

#[test]
fn a_merge_onto_a_base_that_moved_is_admitted_when_its_tree_is_the_local_merge() {
    // Pull request 1's head was cut before pull request 2 landed, so GitHub's merge of it has
    // a tree that is neither parent's. 0.1.13 refused it ("did not incorporate its merge basis")
    // and every pull request merged after another one hit the same refusal.
    for private in [false, true] {
        let mut f = Fixture::new();
        let moved = f.moved_base(("added", b"pull request 1\n"));
        let merged = tree_of(
            f.dir.path(),
            &[
                ("added", b"pull request 1\n"),
                ("landed", b"pull request 2\n"),
            ],
        );
        f.merge_moved_base(&moved, &merged);
        if private {
            privatize(&mut f.api.responses);
        }
        assert!(
            f.verify().is_ok(),
            "the GitHub merge of a bot head onto a moved base must be admitted (private: \
             {private}): {:?}",
            f.verify()
        );
    }
}

#[test]
fn a_merge_carrying_a_change_beyond_the_local_merge_refuses() {
    // The merge tree is the computed merge plus one file nobody reviewed: authored by hand, not
    // by the merge.
    for private in [false, true] {
        let mut f = Fixture::new();
        let moved = f.moved_base(("added", b"pull request 1\n"));
        let tampered = tree_of(
            f.dir.path(),
            &[
                ("added", b"pull request 1\n"),
                ("landed", b"pull request 2\n"),
                ("unreviewed", b"not in either parent\n"),
            ],
        );
        f.merge_moved_base(&moved, &tampered);
        if private {
            privatize(&mut f.api.responses);
        }
        let error = f
            .verify()
            .expect_err("a merge tree beyond the local merge was admitted");
        assert!(
            error.to_string().contains("is not the local merge"),
            "refused for another reason (private: {private}): {error:#}"
        );
    }
}

#[test]
fn a_conflicting_merge_refuses_even_when_its_tree_is_the_conflicted_merge() {
    // Both sides add the same path with different content. The recorded tree is the very tree
    // git writes for that conflict, so tree equality alone would admit it; the conflict itself
    // must refuse, because a conflicted merge was resolved by somebody.
    let mut f = Fixture::private();
    let moved = f.moved_base(("landed", b"pull request 1\n"));
    let (conflicted, clean) = written_merge_tree(f.dir.path(), &moved.base, &moved.head);
    assert!(!clean, "fixture must conflict");
    f.merge_moved_base(&moved, &conflicted);
    privatize(&mut f.api.responses);
    let error = f.verify().expect_err("a conflicting merge was admitted");
    assert!(
        error.to_string().contains("conflicts"),
        "refused for another reason: {error:#}"
    );
}

#[test]
fn worktree_attributes_cannot_steer_the_local_merge() {
    // A `.gitattributes` in the checkout that runs the proof would let a union merge resolve a
    // conflict silently. The local merge reads no attributes from the worktree.
    let mut f = Fixture::private();
    let moved = f.moved_base(("landed", b"pull request 1\n"));
    std::fs::write(f.dir.path().join(".gitattributes"), "* merge=union\n").unwrap();
    let (united, clean) = written_merge_tree(f.dir.path(), &moved.base, &moved.head);
    assert!(clean, "fixture attributes must resolve the conflict");
    f.merge_moved_base(&moved, &united);
    privatize(&mut f.api.responses);
    assert!(
        f.verify().is_err(),
        "worktree attributes steered the local merge"
    );
}

#[test]
fn repository_info_attributes_cannot_steer_the_local_merge() {
    // `--attr-source` replaces the worktree's attributes and `core.attributesFile` is pinned,
    // but `$GIT_DIR/info/attributes` is still read: a union (or any configured) merge driver
    // there resolves the conflict and the local merge reports it clean.
    let mut f = Fixture::private();
    let moved = f.moved_base(("landed", b"pull request 1\n"));
    let info = f.dir.path().join(".git").join("info");
    std::fs::create_dir_all(&info).unwrap();
    std::fs::write(info.join("attributes"), "* merge=union\n").unwrap();
    let (united, clean) = written_merge_tree(f.dir.path(), &moved.base, &moved.head);
    assert!(clean, "fixture attributes must resolve the conflict");
    f.merge_moved_base(&moved, &united);
    privatize(&mut f.api.responses);
    assert!(
        f.verify().is_err(),
        "repository info/attributes steered the local merge"
    );
}

/// A tree holding one directory `dir` with `files`.
fn dir_tree(root: &Path, dir: &str, files: &[(&str, &[u8])]) -> String {
    let inner = tree_of(root, files);
    git(
        root,
        &["mktree"],
        format!("040000 tree {inner}\t{dir}\n").as_bytes(),
    )
}

impl Fixture {
    /// Like `moved_base`, but every tree is chosen: a bot commit after the baseline carries
    /// `common`, pull request 2 moves it to `base` and is merged by GitHub, and pull request 1's
    /// head moves it to `head`.
    fn moved_base_from(&mut self, common: &str, base: &str, head: &str) -> MovedBase {
        let root = self.dir.path().to_path_buf();
        let start = commit(&root, common, &[&self.baseline], false, "common");
        let side = commit(&root, base, &[&start], false, "pull request 2");
        let merged = commit(&root, base, &[&start, &side], true, "merge pull request 2");
        let head = commit(&root, head, &[&start], false, "pull request 1");
        let tree = std::mem::replace(&mut self.tree, base.to_owned());
        self.prove_merge(merged.clone(), start, side, 2);
        self.tree = tree;
        MovedBase { base: merged, head }
    }
}

#[test]
fn repository_merge_config_cannot_make_a_conflicting_merge_clean() {
    // Repository config that is not a merge driver still changes what a clean merge means.
    // `merge.directoryRenames=true` moves a file added under a renamed directory without a
    // conflict, and `merge.renormalize` with `core.autocrlf` discards a line-ending change that
    // otherwise conflicts with an edit. Both are pinned to Git's default for the local merge.
    type Case = (
        &'static [(&'static str, &'static str)],
        fn(&Path) -> [String; 3],
    );
    let cases: [Case; 2] = [
        (&[("merge.directoryRenames", "true")], |root| {
            [
                dir_tree(root, "a", &[("x", b"x\n")]),
                dir_tree(root, "b", &[("x", b"x\n")]),
                dir_tree(root, "a", &[("x", b"x\n"), ("y", b"y\n")]),
            ]
        }),
        (
            &[("core.autocrlf", "true"), ("merge.renormalize", "true")],
            |root| {
                [
                    tree_of(root, &[("f", b"line\r\n")]),
                    tree_of(root, &[("f", b"line\n")]),
                    tree_of(root, &[("f", b"line\r\nmore\r\n")]),
                ]
            },
        ),
    ];
    for (config, trees) in cases {
        for private in [false, true] {
            let mut f = Fixture::new();
            let root = f.dir.path().to_path_buf();
            let [common, base, head] = trees(&root);
            let moved = f.moved_base_from(&common, &base, &head);
            let (_, clean) = written_merge_tree(&root, &moved.base, &moved.head);
            assert!(!clean, "fixture must conflict under Git's defaults");
            for (key, value) in config {
                git(&root, &["config", key, value], b"");
            }
            let (steered, clean) = written_merge_tree(&root, &moved.base, &moved.head);
            assert!(
                clean,
                "fixture config must resolve the conflict ({config:?})"
            );
            f.merge_moved_base(&moved, &steered);
            if private {
                privatize(&mut f.api.responses);
            }
            let error = f
                .verify()
                .expect_err("repository merge config made a conflicting merge clean");
            assert!(
                format!("{error:#}").contains("conflicts"),
                "refused for another reason ({config:?}, private: {private}): {error:#}"
            );
        }
    }
}

#[test]
fn repository_merge_driver_config_cannot_steer_the_local_merge() {
    // `merge.default` picks the driver for every path without a `merge` attribute, so a union
    // default resolves the conflict; a `merge.<name>.driver` can shadow a built-in driver. The
    // repository's own config is not overridden by the pinned global and system config.
    for config in [
        &[("merge.default", "union")][..],
        &[("merge.steer.driver", "true")][..],
    ] {
        let mut f = Fixture::private();
        let moved = f.moved_base(("landed", b"pull request 1\n"));
        let root = f.dir.path().to_path_buf();
        git(&root, &["config", "merge.default", "union"], b"");
        let (united, clean) = written_merge_tree(&root, &moved.base, &moved.head);
        assert!(clean, "fixture config must resolve the conflict");
        git(&root, &["config", "--unset", "merge.default"], b"");
        for (key, value) in config {
            git(&root, &["config", key, value], b"");
        }
        f.merge_moved_base(&moved, &united);
        privatize(&mut f.api.responses);
        let error = f
            .verify()
            .expect_err("repository merge config steered the local merge");
        assert!(
            format!("{error:#}").contains("configured merge driver"),
            "refused for another reason ({config:?}): {error:#}"
        );
    }
}

#[test]
fn an_update_branch_merge_carrying_a_change_beyond_its_parents_refuses() {
    // The update-branch commit is itself a GitHub two-parent merge (prior head, base). Its tree
    // is bound only to the final merge's tree, and the final merge's local merge of (base,
    // update) is trivially the update's tree, so nothing recomputes the update's own merge.
    let bot = format!("{BOT_NAME} <{BOT_EMAIL}> 1700000000 +0000");
    let github = "GitHub <noreply@github.com> 1700000000 +0000";
    let mut control = UpdateFixture::new();
    let parents = control.update_parents();
    control.replace_update_raw(&bot, github, &parents);
    for (entrypoint, result) in ["verify_publication", "verify_pre_push"]
        .into_iter()
        .zip(control.verify())
    {
        assert!(
            result.is_ok(),
            "control refused by {entrypoint}: {result:?}"
        );
    }

    let mut f = UpdateFixture::new();
    let root = f.dir.path().to_path_buf();
    let accepted = git(&root, &["hash-object", "-w", "--stdin"], b"accepted\n");
    let extra = git(
        &root,
        &["hash-object", "-w", "--stdin"],
        b"in neither parent\n",
    );
    f.tree = git(
        &root,
        &["mktree"],
        format!("100644 blob {accepted}\taccepted\n100644 blob {extra}\tunreviewed\n").as_bytes(),
    );
    let parents = f.update_parents();
    f.replace_update_raw(&bot, github, &parents);
    f.assert_refused("an update-branch merge whose tree is not the local merge of its parents");
}

#[test]
fn every_private_remote_read_is_required_and_account_fields_fail_closed() {
    let valid = Fixture::private();
    for path in valid.api.responses.keys() {
        let mut f = Fixture::private();
        f.api.responses.remove(path);
        assert!(f.verify().is_err(), "missing private read admitted: {path}");
    }
    for field in [
        "/merged_by/login",
        "/merged_by/type",
        "/merged_by/id",
        "/user/login",
        "/user/type",
        "/user/id",
    ] {
        let mut f = Fixture::private();
        *f.pr().pointer_mut(field).unwrap() = Value::Null;
        assert!(f.verify().is_err(), "missing private pr {field} admitted");
    }
}

// Review probes for issue #29: each asserts a refusal the private proof promises.

fn assert_private_refusal(f: &Fixture, needle: &str, what: &str) {
    let error = f
        .verify()
        .expect_err(&format!("{what} admitted on a private repository"));
    assert!(
        format!("{error:#}").contains(needle),
        "{what} refused for another reason: {error:#}"
    );
}

#[test]
fn review_private_octopus_merge_refuses() {
    let mut f = Fixture::new();
    let tree = f.tree.clone();
    let baseline = f.baseline.clone();
    let topic = f.topic.clone();
    let other = commit(f.dir.path(), &tree, &[&baseline], false, "other");
    f.replace_merge(&tree, &[&baseline, &topic, &other]);
    privatize(&mut f.api.responses);
    assert_private_refusal(&f, "one or two parents", "octopus merge");
}

#[test]
fn review_private_rebase_merge_refuses() {
    // A rebase merge writes one GitHub-committed single-parent commit per head commit; the last
    // is the pull request's merge_commit_sha. None of them is a two-parent merge.
    let mut f = Fixture::new();
    let tree = f.tree.clone();
    let baseline = f.baseline.clone();
    let first = commit(f.dir.path(), &tree, &[&baseline], true, "rebased one");
    let last = commit(f.dir.path(), &tree, &[&first], true, "rebased two");
    f.candidate = commit(f.dir.path(), &tree, &[&last], false, "candidate");
    f.merge = last.clone();
    f.api.responses.get_mut(REF).unwrap()["object"]["sha"] = json!(last);
    let pr = json!({"number":1,"state":"closed","merged":true,"merge_commit_sha":last,"merged_by":{"login":BOT_NAME},"head":{"sha":f.topic,"repo":{"full_name":REPOSITORY,"id":123}},"base":{"ref":"main","sha":baseline,"repo":{"full_name":REPOSITORY,"id":123}}});
    for (sha, parent) in [(&first, &baseline), (&last, &first)] {
        f.api.responses.insert(format!("{ROOT}/commits/{sha}"), json!({
            "sha":sha,"author":{"login":BOT_NAME},"committer":{"login":"web-flow"},
            "commit":{"author":{"name":BOT_NAME,"email":BOT_EMAIL},"committer":{"name":"GitHub","email":"noreply@github.com"},"tree":{"sha":tree},"verification":{"verified":true,"reason":"valid"}},
            "parents":[{"sha":parent}]
        }));
        f.api.responses.insert(
            format!("{ROOT}/commits/{sha}/pulls?per_page=100&page=1"),
            json!([pr.clone()]),
        );
    }
    f.api.responses.insert(format!("{ROOT}/pulls/1"), pr);
    privatize(&mut f.api.responses);
    assert!(
        f.verify().is_err(),
        "rebase merge admitted on a private repository"
    );
}

#[test]
fn review_private_pull_request_from_another_repository_refuses() {
    for side in ["head", "base"] {
        for (name, id) in [("other/repository", 123), (REPOSITORY, 999)] {
            let mut f = Fixture::private();
            f.pr()[side]["repo"] = json!({"full_name":name,"id":id});
            assert_private_refusal(&f, "not same-repository", "foreign pull request record");
        }
    }
}

type VisibilityCase = (&'static str, fn(&mut Value));

#[test]
fn review_private_visibility_edge_cases_refuse() {
    let cases: [VisibilityCase; 4] = [
        ("private flag with internal visibility", |root| {
            root["visibility"] = json!("internal")
        }),
        ("visibility field absent", |root| {
            root.as_object_mut().unwrap().remove("visibility");
        }),
        ("private flag as a string", |root| {
            root["private"] = json!("true")
        }),
        ("visibility in another case", |root| {
            root["visibility"] = json!("Private")
        }),
    ];
    for (what, change) in cases {
        let mut f = Fixture::private();
        change(f.api.responses.get_mut(ROOT).unwrap());
        assert_private_refusal(&f, "visibility", what);
    }
}

#[test]
fn review_private_policy_repository_id_mismatch_refuses() {
    let mut f = Fixture::private();
    f.policy.repositories.get_mut(REPOSITORY).unwrap().id = "124".into();
    assert_private_refusal(
        &f,
        "identity mismatch",
        "repository id other than the policy's",
    );
}

#[test]
fn review_private_update_branch_merged_by_a_person_refuses() {
    let mut f = UpdateFixture::new();
    privatize(&mut f.api.responses);
    f.pr()["merged_by"] = json!({"login":BOT_NAME,"type":"User","id":BOT_USER_ID});
    f.assert_refused("private update merge merged by a user account");
}
