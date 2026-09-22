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

/// A stale PR basis is refused when the base carried content the head could have dropped.
///
/// The base advanced past the fork point with a new file, and the merge adopted the head's tree,
/// so the base's file is gone from the merge. That is the hazard the basis check exists for.
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
        error
            .to_string()
            .contains("did not incorporate its merge basis"),
        "refused for the basis, not for another reason: {error:#}"
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
