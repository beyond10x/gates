//! `b10x-gates bot [--repository <owner>/<repo>] -- delete-branch <branch>` checks a
//! remote branch through the REST API as the App and deletes it with a Git push that
//! carries the checked tip, only when its tip is an ancestor of the default branch
//! (`story:bot-delete-branch` and
//! `story:bot-delete-branch-defaults`, modelled as `gates.delivery.DeleteBranch` in
//! `ess/domains/delivery.yaml`). Without `--repository` the repository is the
//! installed hooks' configuration's. Each test is named
//! after the outcome it holds the implementation to. GitHub is a fake behind
//! `delivery::RemoteBranches`, so no credential is ever minted; the compare-and-delete
//! (`story:bot-delete-branch-atomic`) also runs for real against a local bare
//! repository.
use b10x_gates::{
    bot_args::{check, delete_branch, delete_branch_repository},
    delivery::{
        CompareAndDelete, RemoteBranches, api_path_admitted, bot_git, compare_and_delete_branch,
        delete_remote_branch,
    },
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    ffi::OsStr,
    process::{Command, Stdio},
};

const REPOSITORY: &str = "example/sample";
const TIP: &str = "1111111111111111111111111111111111111111";
const MOVED: &str = "2222222222222222222222222222222222222222";

fn args(line: &str) -> Vec<String> {
    line.split_whitespace().map(String::from).collect()
}

/// GitHub as a table of answers per path. A path answered more than once takes its
/// answers in order and repeats the last; `None` is a 404. An unexpected path panics.
#[derive(Default)]
struct Fake {
    answers: RefCell<HashMap<String, VecDeque<Option<Value>>>>,
    reads: RefCell<Vec<String>>,
    deletes: RefCell<Vec<String>>,
}

impl Fake {
    fn answer(self, path: &str, value: Option<Value>) -> Self {
        self.answers
            .borrow_mut()
            .entry(path.to_string())
            .or_default()
            .push_back(value);
        self
    }

    /// A repository whose default branch is `main` and a branch `name` at `TIP`.
    fn merged(name: &str, encoded: &str, status: &str) -> Self {
        Fake::compared(
            name,
            encoded,
            json!({"status": status, "merge_base_commit": {"sha": TIP}}),
        )
    }

    fn compared(name: &str, encoded: &str, comparison: Value) -> Self {
        Fake::default()
            .answer(
                "/repos/example/sample",
                Some(json!({"default_branch": "main"})),
            )
            .answer(
                &format!("/repos/example/sample/branches/{encoded}"),
                Some(branch(name, TIP, false)),
            )
            .answer(&compare_path(), Some(comparison))
            .answer(&rules_path(encoded), Some(bot_authority()))
    }
}

impl RemoteBranches for Fake {
    fn read(&self, path: &str) -> anyhow::Result<Option<Value>> {
        self.reads.borrow_mut().push(path.to_string());
        guard(path)?;
        let mut answers = self.answers.borrow_mut();
        let queue = answers
            .get_mut(path)
            .unwrap_or_else(|| panic!("unexpected GitHub read {path}"));
        Ok(if queue.len() > 1 {
            queue.pop_front().unwrap()
        } else {
            queue.front().cloned().unwrap()
        })
    }

    fn delete(
        &self,
        repository: &str,
        branch: &str,
        tip: &str,
    ) -> anyhow::Result<CompareAndDelete> {
        self.deletes
            .borrow_mut()
            .push(format!("{repository} refs/heads/{branch} at {tip}"));
        Ok(CompareAndDelete::Deleted)
    }
}

/// The deletion the fake records for `branch` of `example/sample` at `TIP`.
fn deleted(branch: &str) -> String {
    format!("{REPOSITORY} refs/heads/{branch} at {TIP}")
}

/// The real client's path guard: a path `Github::api_response` refuses is refused here.
fn guard(path: &str) -> anyhow::Result<()> {
    anyhow::ensure!(api_path_admitted(path), "invalid GitHub API path");
    Ok(())
}

/// The comparison of `TIP` with `main`, its `...` separator percent-encoded so the
/// client's `..` guard admits it.
fn compare_path() -> String {
    format!("/repos/example/sample/compare/{TIP}%2E%2E%2Emain")
}

fn rules_path(encoded: &str) -> String {
    format!("/repos/example/sample/rules/branches/{encoded}?per_page=100")
}

fn rule(kind: &str) -> Value {
    json!({"type": kind, "ruleset_source_type": "Organization", "ruleset_id": 1})
}

/// The rules the organization's bot-authority ruleset puts on a non-default branch, as
/// GitHub answered for beyond10x/gates: one `deletion` among them.
fn bot_authority() -> Value {
    Value::Array(
        [
            "creation",
            "update",
            "deletion",
            "non_fast_forward",
            "commit_author_email_pattern",
            "committer_email_pattern",
        ]
        .into_iter()
        .map(rule)
        .collect(),
    )
}

/// A merged branch `wave/one` whose rules are `rules` (`None` is a 404).
fn ruled(rules: Option<Value>) -> Fake {
    Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": "main"})),
        )
        .answer(
            "/repos/example/sample/branches/wave/one",
            Some(branch("wave/one", TIP, false)),
        )
        .answer(
            &compare_path(),
            Some(json!({"status": "ahead", "merge_base_commit": {"sha": TIP}})),
        )
        .answer(&rules_path("wave/one"), rules)
}

/// A branch answer as GitHub gives it under the organization's bot-authority ruleset:
/// `protected` is true for every branch a ruleset covers, so only
/// `protection.enabled` says whether classic branch protection is on.
fn branch(name: &str, tip: &str, protected: bool) -> Value {
    json!({
        "name": name,
        "protected": true,
        "protection": {"enabled": protected, "required_status_checks": {"enforcement_level": "off"}},
        "commit": {"sha": tip}
    })
}

fn deletion(branch: &str) -> b10x_gates::bot_args::BranchDeletion {
    delete_branch(&args(&format!("delete-branch {branch}")), Some(REPOSITORY))
        .unwrap_or_else(|e| panic!("`{branch}` refused: {e:#}"))
}

fn refused(fake: &Fake, branch: &str) -> String {
    let error =
        delete_remote_branch(fake, &deletion(branch)).expect_err("the deletion was not refused");
    assert!(
        fake.deletes.borrow().is_empty(),
        "a refused deletion still sent DELETE: {:?}",
        fake.deletes.borrow()
    );
    format!("{error:#}")
}

fn shape_refusal(line: &str, repository: Option<&str>) -> String {
    let checked = check(&args(line), repository);
    let parsed = delete_branch(&args(line), repository);
    match (checked, parsed) {
        (Err(checked), Err(parsed)) => {
            let text = format!("{checked:#}");
            assert_eq!(text, format!("{parsed:#}"), "{line}");
            text
        }
        _ => panic!("`{line}` passed the delete-branch check"),
    }
}

#[test]
fn deletes_a_merged_branch() {
    for status in ["ahead", "identical"] {
        let fake = Fake::merged("wave/one", "wave/one", status);
        let printed = delete_remote_branch(&fake, &deletion("wave/one"))
            .unwrap_or_else(|e| panic!("{status}: {e:#}"));
        assert_eq!(printed, format!("deleted wave/one at {TIP}"));
        assert_eq!(
            *fake.deletes.borrow(),
            vec![deleted("wave/one")],
            "{status}"
        );
        // The branch is read twice: before the comparison and again before the deletion.
        let reads = fake.reads.borrow();
        assert_eq!(
            reads
                .iter()
                .filter(|r| *r == "/repos/example/sample/branches/wave/one")
                .count(),
            2,
            "{reads:?}"
        );
    }
    // `refs/heads/<b>` names the same branch, never anything else.
    let fake = Fake::merged("wave/one", "wave/one", "ahead");
    delete_remote_branch(&fake, &deletion("refs/heads/wave/one")).unwrap();
    assert_eq!(*fake.deletes.borrow(), vec![deleted("wave/one")]);
}

/// Whatever passes the name rules cannot change the request path: each segment is
/// percent-encoded, `/` separates segments and nothing else does. The deletion is no
/// request path: it names the branch as it is.
#[test]
fn encodes_branch_path_segments() {
    let fake = Fake::merged("wave/a#b%c&d+e", "wave/a%23b%25c%26d%2Be", "ahead");
    delete_remote_branch(&fake, &deletion("wave/a#b%c&d+e")).unwrap();
    for path in [
        "/repos/example/sample/branches/wave/a%23b%25c%26d%2Be".to_string(),
        rules_path("wave/a%23b%25c%26d%2Be"),
    ] {
        assert!(fake.reads.borrow().contains(&path), "{path}");
    }
    assert_eq!(*fake.deletes.borrow(), vec![deleted("wave/a#b%c&d+e")]);
}

#[test]
fn refuses_the_default_branch() {
    let fake = Fake::merged("main", "main", "identical");
    let text = refused(&fake, "main");
    assert!(text.contains("default branch"), "{text}");
    assert!(text.contains("`main`"), "{text}");
}

#[test]
fn refuses_a_protected_branch() {
    let fake = Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": "main"})),
        )
        .answer(
            "/repos/example/sample/branches/release",
            Some(branch("release", TIP, true)),
        );
    let text = refused(&fake, "release");
    assert!(text.contains("protected"), "{text}");
    assert!(text.contains("`release`"), "{text}");
    // Classic protection is decided by `protection.enabled`, whatever `protected` says.
    let fake = Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": "main"})),
        )
        .answer(
            "/repos/example/sample/branches/release",
            Some(json!({
                "name": "release",
                "protected": false,
                "protection": {"enabled": true},
                "commit": {"sha": TIP}
            })),
        );
    let text = refused(&fake, "release");
    assert!(text.contains("protected branch `release`"), "{text}");
}

/// `protected` is true for every branch a ruleset covers (observed on beyond10x/gates,
/// where `GET /branches/<b>/protection` answered 404 for each of them): a merged
/// branch with classic protection off and only the bot-authority rules is deleted.
#[test]
fn deletes_a_merged_branch_under_the_bot_authority_ruleset() {
    let fake = ruled(Some(bot_authority()));
    let printed = delete_remote_branch(&fake, &deletion("wave/one")).unwrap_or_else(|e| {
        panic!("a ruleset-only branch with protection.enabled false was refused: {e:#}")
    });
    assert_eq!(printed, format!("deleted wave/one at {TIP}"));
    assert_eq!(*fake.deletes.borrow(), vec![deleted("wave/one")]);
}

/// A branch answer that does not say, as a JSON boolean, whether classic protection is
/// enabled is refused and names `protection.enabled`; `protected` never stands in.
#[test]
fn refuses_a_branch_without_protection_enabled() {
    for answer in [
        json!({"name": "wave/one", "protected": false, "commit": {"sha": TIP}}),
        json!({"name": "wave/one", "protected": true, "commit": {"sha": TIP}}),
        json!({"name": "wave/one", "protected": false, "protection": {}, "commit": {"sha": TIP}}),
        json!({"name": "wave/one", "protected": false, "protection": null, "commit": {"sha": TIP}}),
        json!({
            "name": "wave/one",
            "protected": false,
            "protection": {"enabled": "false"},
            "commit": {"sha": TIP}
        }),
        json!({
            "name": "wave/one",
            "protected": false,
            "protection": {"enabled": 0},
            "commit": {"sha": TIP}
        }),
    ] {
        let fake = Fake::default()
            .answer(
                "/repos/example/sample",
                Some(json!({"default_branch": "main"})),
            )
            .answer(
                "/repos/example/sample/branches/wave/one",
                Some(answer.clone()),
            );
        let text = refused(&fake, "wave/one");
        assert!(text.contains("protection.enabled"), "{answer}: {text}");
        assert!(text.contains("`wave/one`"), "{answer}: {text}");
    }
}

#[test]
fn refuses_an_unmerged_branch() {
    for status in ["diverged", "behind"] {
        let fake = Fake::merged("wave/one", "wave/one", status);
        let text = refused(&fake, "wave/one");
        assert!(text.contains("not merged"), "{status}: {text}");
        assert!(text.contains(status), "{status}: {text}");
        assert!(text.contains("--method DELETE"), "{status}: {text}");
    }
    // An `ahead` answer whose merge base is not the tip is not an ancestry proof.
    for comparison in [
        json!({"status": "ahead", "merge_base_commit": {"sha": MOVED}}),
        json!({"status": "ahead"}),
        json!({}),
    ] {
        let fake = Fake::compared("wave/one", "wave/one", comparison.clone());
        let text = refused(&fake, "wave/one");
        assert!(text.contains("not merged"), "{comparison}: {text}");
    }
}

/// `story:bot-delete-branch-compare`: 0.1.18 read `compare/<tip>...<default>`, which
/// the client's `..` guard refused before sending, so every merged branch was refused.
/// Observed on `wave/2026-10-13-w3`; the double applies the real guard.
#[test]
fn deletes_a_merged_branch_through_an_admitted_comparison_path() {
    let fake = Fake::merged("wave/2026-10-13-w3", "wave/2026-10-13-w3", "ahead");
    let printed = delete_remote_branch(&fake, &deletion("wave/2026-10-13-w3"))
        .unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(printed, format!("deleted wave/2026-10-13-w3 at {TIP}"));
    assert_eq!(*fake.deletes.borrow(), vec![deleted("wave/2026-10-13-w3")]);
    assert!(
        fake.reads.borrow().contains(&compare_path()),
        "{:?}",
        fake.reads.borrow()
    );
}

/// Every path `delete_remote_branch` requests passes the guard; all five are reads,
/// and the one deletion is the compare-and-delete.
#[test]
fn every_requested_path_passes_the_client_guard() {
    for (name, encoded) in [
        ("wave/2026-10-13-w3", "wave/2026-10-13-w3"),
        ("wave/one", "wave/one"),
        ("wave/a#b%c&d+e", "wave/a%23b%25c%26d%2Be"),
    ] {
        let fake = Fake::merged(name, encoded, "identical");
        delete_remote_branch(&fake, &deletion(name)).unwrap_or_else(|e| panic!("{name}: {e:#}"));
        let requested = fake.reads.borrow();
        assert_eq!(requested.len(), 5, "{name}: {requested:?}");
        for path in requested.iter() {
            assert!(api_path_admitted(path), "{name}: guard refuses {path}");
        }
        assert_eq!(*fake.deletes.borrow(), vec![deleted(name)], "{name}");
    }
}

/// `comparison-unreadable`: a comparison GitHub does not answer (a 404) is refused and
/// nothing is deleted.
#[test]
fn refuses_an_unreadable_comparison() {
    let fake = Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": "main"})),
        )
        .answer(
            "/repos/example/sample/branches/wave/one",
            Some(branch("wave/one", TIP, false)),
        )
        .answer(&compare_path(), None);
    let text = refused(&fake, "wave/one");
    assert!(text.contains("cannot compare"), "{text}");
}

#[test]
fn refuses_a_moved_tip() {
    let fake = Fake::merged("wave/one", "wave/one", "ahead").answer(
        "/repos/example/sample/branches/wave/one",
        Some(branch("wave/one", MOVED, false)),
    );
    let text = refused(&fake, "wave/one");
    assert!(text.contains("moved"), "{text}");
    assert!(text.contains(TIP) && text.contains(MOVED), "{text}");
    // Gone between the two reads is refused too.
    let fake = Fake::merged("wave/one", "wave/one", "ahead")
        .answer("/repos/example/sample/branches/wave/one", None);
    let text = refused(&fake, "wave/one");
    assert!(text.contains("wave/one"), "{text}");
}

/// A bare repository standing in for the Git remote of `example/sample`.
struct BareRemote {
    dir: tempfile::TempDir,
}

impl BareRemote {
    /// `main` and `wave/one` at one commit, which is returned.
    fn new() -> (Self, String) {
        let remote = BareRemote {
            dir: tempfile::tempdir().unwrap(),
        };
        remote.git(&["init", "--quiet", "--bare"]);
        let tip = remote.commit(None);
        remote.git(&["update-ref", "refs/heads/main", &tip]);
        remote.git(&["update-ref", "refs/heads/wave/one", &tip]);
        (remote, tip)
    }

    fn command(&self, args: &[&str]) -> std::process::Output {
        Command::new("git")
            .arg("--git-dir")
            .arg(self.dir.path())
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
            .unwrap()
    }

    fn git(&self, args: &[&str]) -> String {
        let output = self.command(args);
        assert!(
            output.status.success(),
            "git {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    /// A new commit of the empty tree on `parent`.
    fn commit(&self, parent: Option<&str>) -> String {
        let tree = self.git(&["mktree"]);
        let mut args = vec!["commit-tree", tree.as_str(), "-m", "change"];
        args.extend(parent.map(|parent| ["-p", parent]).into_iter().flatten());
        self.git(&args)
    }

    /// Where `refs/heads/<branch>` points; `None` when it does not exist.
    fn tip(&self, branch: &str) -> Option<String> {
        let output = self.command(&[
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("refs/heads/{branch}"),
        ]);
        output
            .status
            .success()
            .then(|| String::from_utf8(output.stdout).unwrap().trim().to_string())
    }

    fn url(&self) -> &str {
        self.dir.path().to_str().unwrap()
    }
}

/// GitHub's reads from the fake, and the real compare-and-delete against `remote`.
/// `between` runs after the last read and before the deletion, where a push can land.
struct OverGit<'a> {
    reads: Fake,
    remote: &'a BareRemote,
    between: &'a dyn Fn(&BareRemote),
}

impl RemoteBranches for OverGit<'_> {
    fn read(&self, path: &str) -> anyhow::Result<Option<Value>> {
        self.reads.read(path)
    }

    fn delete(
        &self,
        repository: &str,
        branch: &str,
        tip: &str,
    ) -> anyhow::Result<CompareAndDelete> {
        assert_eq!(repository, REPOSITORY);
        let reads = self.reads.reads.borrow().clone();
        assert_eq!(
            reads
                .iter()
                .filter(|path| *path == "/repos/example/sample/branches/wave/one")
                .count(),
            2,
            "the deletion came before the last read: {reads:?}"
        );
        (self.between)(self.remote);
        compare_and_delete_branch(self.remote.url(), branch, tip, None)
    }
}

/// `delete-branch wave/one` where GitHub answers that `wave/one` is merged at `tip`.
fn delete_over_git(
    remote: &BareRemote,
    tip: &str,
    between: &dyn Fn(&BareRemote),
) -> anyhow::Result<String> {
    let reads = Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": "main"})),
        )
        .answer(
            "/repos/example/sample/branches/wave/one",
            Some(branch("wave/one", tip, false)),
        )
        .answer(
            &format!("/repos/example/sample/compare/{tip}%2E%2E%2Emain"),
            Some(json!({"status": "identical", "merge_base_commit": {"sha": tip}})),
        )
        .answer(&rules_path("wave/one"), Some(bot_authority()));
    let api = OverGit {
        reads,
        remote,
        between,
    };
    delete_remote_branch(&api, &deletion("wave/one"))
}

/// `story:bot-delete-branch-atomic`: a push that moves the tip after the last read and
/// before the deletion is never deleted. The remote keeps the branch at the moved tip,
/// and the refusal names it.
#[test]
fn keeps_a_branch_whose_tip_moves_after_the_last_read() {
    let (remote, tip) = BareRemote::new();
    let moved = RefCell::new(None);
    let result = delete_over_git(&remote, &tip, &|remote| {
        let next = remote.commit(Some(tip.as_str()));
        remote.git(&["update-ref", "refs/heads/wave/one", &next]);
        *moved.borrow_mut() = Some(next);
    });
    let moved = moved
        .into_inner()
        .expect("the deletion was never attempted");
    assert_eq!(
        remote.tip("wave/one").as_deref(),
        Some(moved.as_str()),
        "the branch moved to {moved} after the last read was not kept: {result:?}"
    );
    let text = format!("{:#}", result.expect_err("the deletion was not refused"));
    assert!(
        text.contains(&format!("moved from {tip} to {moved}")),
        "{text}"
    );
    assert!(text.contains("kept"), "{text}");
}

/// The control: a tip that did not move is deleted through Git, and only
/// `refs/heads/wave/one` is: `main` and a tag of the same name stay.
#[test]
fn deletes_through_git_at_the_checked_tip_and_nothing_else() {
    let (remote, tip) = BareRemote::new();
    remote.git(&["update-ref", "refs/tags/wave/one", &tip]);
    let printed = delete_over_git(&remote, &tip, &|_| {}).unwrap_or_else(|e| panic!("{e:#}"));
    assert_eq!(printed, format!("deleted wave/one at {tip}"));
    assert_eq!(remote.tip("wave/one"), None);
    assert_eq!(remote.tip("main").as_deref(), Some(tip.as_str()));
    assert_eq!(remote.git(&["rev-parse", "refs/tags/wave/one"]), tip);
}

/// A branch someone deleted after the last read is refused as gone, naming the tip it
/// was checked at.
#[test]
fn refuses_a_branch_deleted_after_the_last_read() {
    let (remote, tip) = BareRemote::new();
    let result = delete_over_git(&remote, &tip, &|remote| {
        remote.git(&["update-ref", "-d", "refs/heads/wave/one"]);
    });
    let text = format!(
        "{:#}",
        result.expect_err("a deleted branch was reported deleted")
    );
    assert!(text.contains("no longer exists"), "{text}");
    assert!(text.contains(&tip), "{text}");
    assert_eq!(remote.tip("main").as_deref(), Some(tip.as_str()));
}

/// A deletion the remote applied but whose report never reached Git (the remote's
/// process ends once the ref transaction is committed, as a lost connection would) is
/// told as an unknown outcome, never as "the bot deleted nothing".
#[test]
fn an_unreported_deletion_is_told_as_unknown() {
    use std::os::unix::fs::PermissionsExt;
    let (remote, tip) = BareRemote::new();
    let result = delete_over_git(&remote, &tip, &|remote| {
        let hook = remote.dir.path().join("hooks/reference-transaction");
        std::fs::create_dir_all(hook.parent().unwrap()).unwrap();
        std::fs::write(
            &hook,
            "#!/bin/sh\n[ \"$1\" = committed ] && kill -9 $PPID\nexit 0\n",
        )
        .unwrap();
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    });
    assert_eq!(
        remote.tip("wave/one"),
        None,
        "fixture: the remote did not apply the deletion: {result:?}"
    );
    let text = format!(
        "{:#}",
        result.expect_err("an unreported deletion was reported deleted")
    );
    assert!(text.contains("outcome is unknown"), "{text}");
    assert!(text.contains("no longer exists"), "{text}");
    assert!(!text.contains("deleted nothing"), "{text}");
}

/// The Git deletion compares only a full object id and addresses only a branch name the
/// name rules admit; anything else is refused before Git runs and deletes nothing.
#[test]
fn the_git_deletion_refuses_what_it_cannot_compare() {
    let (remote, tip) = BareRemote::new();
    let upper = tip.to_ascii_uppercase();
    let admitted: Vec<String> = [
        ("wave/one", &tip[..12]),
        ("wave/one", "HEAD"),
        ("wave/one", upper.as_str()),
        ("refs/heads/wave/one", tip.as_str()),
        ("wave/*", tip.as_str()),
        ("wave/one:main", tip.as_str()),
        ("a..b", tip.as_str()),
    ]
    .into_iter()
    .filter_map(|(branch, expected)| {
        compare_and_delete_branch(remote.url(), branch, expected, None)
            .ok()
            .map(|outcome| format!("{branch} at {expected}: {outcome:?}"))
    })
    .collect();
    assert!(admitted.is_empty(), "admitted: {admitted:#?}");
    assert_eq!(remote.tip("wave/one").as_deref(), Some(tip.as_str()));
    assert_eq!(remote.tip("main").as_deref(), Some(tip.as_str()));
}

#[test]
fn refuses_an_unknown_branch() {
    let fake = Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": "main"})),
        )
        .answer("/repos/example/sample/branches/gone", None);
    let text = refused(&fake, "gone");
    assert!(text.contains("does not exist"), "{text}");
    assert!(text.contains("`gone`"), "{text}");
    // GitHub answers a renamed branch with its new name; that is not this branch.
    let fake = Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": "main"})),
        )
        .answer(
            "/repos/example/sample/branches/old",
            Some(branch("new", TIP, false)),
        );
    let text = refused(&fake, "old");
    assert!(text.contains("`new`"), "{text}");
}

#[test]
fn refuses_tag_and_invalid_names() {
    let tag = shape_refusal("delete-branch refs/tags/v1", Some(REPOSITORY));
    assert!(tag.contains("refs/tags/v1"), "{tag}");
    assert!(tag.contains("never deletes a tag"), "{tag}");
    for name in [
        "a..b",
        "x:y",
        "foo.lock",
        "refs/heads/",
        "refs/remotes/origin/x",
        "x~1",
        "x^",
        "a?b",
        "a*",
        "a[b",
        "a\\b",
        "a@{1}",
        "a\u{7}b",
        "a/",
        "/a",
        "a//b",
        ".hidden",
        "wave/.x",
        "a.",
        "@",
    ] {
        let text = shape_refusal(&format!("delete-branch {name}"), Some(REPOSITORY));
        assert!(text.contains("branch name"), "{name:?}: {text}");
    }
    // Empty and a space: `args` splits on whitespace, so build them directly.
    for name in ["", "a b"] {
        let line = vec!["delete-branch".to_string(), name.to_string()];
        let text = format!("{:#}", check(&line, Some(REPOSITORY)).unwrap_err());
        assert!(text.contains("branch name"), "{name:?}: {text}");
        assert!(delete_branch(&line, Some(REPOSITORY)).is_err(), "{name:?}");
    }
}

/// A fresh repository in a temporary directory, without installed hooks.
fn repository_without_hooks() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let status = Command::new("git")
        .args(["init", "-q"])
        .current_dir(dir.path())
        .status()
        .unwrap();
    assert!(status.success());
    dir
}

/// Install a hooks configuration naming `repository` in the repository's common
/// directory, as `b10x-gates install` writes it: directory 0700, file `mode`.
fn install_configuration(root: &std::path::Path, repository: &str, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    let directory = root.join(".git/b10x-gates-hooks");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = directory.join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&json!({
            "repository": repository,
            "policy": "policy.json",
            "key": "receipt.key",
            "scanner": "gitleaks",
            "previous": {},
            "retired_pre_push_digest": null,
            "installed_version": "0.0.0"
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(mode)).unwrap();
}

/// Without `--repository`, the repository is the installed hooks' `repository`, as
/// for `commit` and `push`; an explicit `--repository` still wins.
#[test]
fn resolves_the_repository_from_the_installed_configuration() {
    let dir = repository_without_hooks();
    install_configuration(dir.path(), REPOSITORY, 0o600);
    let resolved = delete_branch_repository(dir.path(), None).unwrap();
    assert_eq!(resolved.as_deref(), Some(REPOSITORY));
    let parsed = delete_branch(&args("delete-branch wave/one"), resolved.as_deref()).unwrap();
    assert_eq!(parsed.repository, REPOSITORY);
    check(&args("delete-branch wave/one"), resolved.as_deref()).unwrap();
    // The flag wins over the configuration.
    let flagged = delete_branch_repository(dir.path(), Some("example/other")).unwrap();
    assert_eq!(flagged.as_deref(), Some("example/other"));
    // A configuration others can read is not trusted: its cause is named.
    install_configuration(dir.path(), REPOSITORY, 0o644);
    let text = format!(
        "{:#}",
        delete_branch_repository(dir.path(), None).unwrap_err()
    );
    assert!(text.contains("config.json"), "{text}");
    assert!(text.contains("0644"), "{text}");
    // A configured repository that is not `<owner>/<repo>` is refused, naming it.
    install_configuration(dir.path(), "example/../x", 0o600);
    let text = format!(
        "{:#}",
        delete_branch_repository(dir.path(), None).unwrap_err()
    );
    assert!(text.contains("example/../x"), "{text}");
    assert!(text.contains("config.json"), "{text}");
    // The binary reads the configuration before any bot credential: with the
    // repository resolved, the first refusal is the absent bot configuration.
    install_configuration(dir.path(), REPOSITORY, 0o600);
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .arg("--repo")
        .arg(dir.path())
        .args(["bot", "--", "delete-branch", "wave/one"])
        .env("HOME", home.path())
        .env("B10X_BOT_CONFIG", home.path().join("absent.json"))
        .env("B10X_BOT_KEY", home.path().join("absent.pem"))
        .env_remove("B10X_GATES_POLICY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("--repository"), "{stderr}");
    assert!(stderr.contains("absent.json"), "{stderr}");
}

#[test]
fn refuses_without_repository() {
    let text = shape_refusal("delete-branch wave/one", None);
    assert!(text.contains("--repository <owner>/<repo>"), "{text}");
    assert!(text.contains("b10x-gates install"), "{text}");
    // No flag and no installed configuration: nothing to resolve.
    let dir = repository_without_hooks();
    assert_eq!(delete_branch_repository(dir.path(), None).unwrap(), None);
    // Nor in a directory that is no repository at all.
    let plain = tempfile::tempdir().unwrap();
    assert_eq!(delete_branch_repository(plain.path(), None).unwrap(), None);
    // A repository Git refuses to read is not "no repository": refused with its cause.
    let unreadable = repository_without_hooks();
    let status = Command::new("git")
        .args(["config", "core.repositoryformatversion", "99"])
        .current_dir(unreadable.path())
        .status()
        .unwrap();
    assert!(status.success());
    let text = format!(
        "{:#}",
        delete_branch_repository(unreadable.path(), None)
            .expect_err("a repository Git cannot read was reported as absent")
    );
    assert!(text.contains("could not locate the repository"), "{text}");
    assert!(text.contains("--repository <owner>/<repo>"), "{text}");
    for repository in [
        "",
        "example",
        "example/sample/x",
        "../sample",
        "example/..",
        "a b/c",
    ] {
        let text = shape_refusal("delete-branch wave/one", Some(repository));
        assert!(text.contains("--repository"), "{repository:?}: {text}");
    }
    // The binary refuses before it reads any bot configuration or mints a token. A
    // repository without installed hooks: this checkout may have them installed.
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .arg("--repo")
        .arg(dir.path())
        .args(["bot", "--", "delete-branch", "wave/one"])
        .env("HOME", home.path())
        .env("B10X_BOT_CONFIG", home.path().join("absent.json"))
        .env("B10X_BOT_KEY", home.path().join("absent.pem"))
        .env_remove("B10X_GATES_POLICY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--repository"), "{stderr}");
    assert!(stderr.contains("b10x-gates install"), "{stderr}");
}

#[test]
fn refuses_extra_arguments_and_options() {
    for line in [
        "delete-branch a b",
        "delete-branch --force a",
        "delete-branch -f a",
        "delete-branch",
        "delete-branch -- a",
        "delete-branch a --no-verify",
        "delete-branch --force",
        "delete-branch -f",
    ] {
        let text = shape_refusal(line, Some(REPOSITORY));
        assert!(
            text.contains("bot delete-branch takes exactly one branch and no option"),
            "{line}: {text}"
        );
    }
}

#[test]
fn push_delete_refusal_names_delete_branch() {
    for (line, branch) in [
        ("push --delete origin x", "x"),
        ("push -d origin wave/one", "wave/one"),
        ("push origin :refs/heads/x", "x"),
    ] {
        let text = format!("{:#}", check(&args(line), Some(REPOSITORY)).unwrap_err());
        assert!(
            text.contains(&format!(
                "b10x-gates bot --repository example/sample -- delete-branch {branch}"
            )),
            "{line}: {text}"
        );
        // The raw API route stays, for an unmerged branch only.
        assert!(text.contains("unmerged"), "{line}: {text}");
        assert!(
            text.contains(&format!(
                "--method DELETE --path /repos/example/sample/git/refs/heads/{branch} "
            )),
            "{line}: {text}"
        );
    }
}

/// `delete-branch` is not a Git command the bot passes on: the library's Git route
/// refuses it before Git and names the bot verb, which checks through the REST API and
/// deletes by a push of its own.
#[test]
fn library_git_never_runs_delete_branch() {
    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        "{:#}",
        bot_git(dir.path(), &args("delete-branch wave/one"), None).unwrap_err()
    );
    assert!(text.contains("REST API"), "{text}");
    assert!(text.contains("-- delete-branch <branch>"), "{text}");
    assert!(text.contains("Git push of its own"), "{text}");
    assert!(!text.contains("failed (exit"), "reached Git: {text}");
}

/// A branch no ruleset covers, or only the bot-authority one, is deleted; the rules
/// are read before the DELETE.
#[test]
fn deletes_under_the_bot_authority_ruleset_alone() {
    for rules in [json!([]), bot_authority()] {
        let fake = ruled(Some(rules.clone()));
        delete_remote_branch(&fake, &deletion("wave/one"))
            .unwrap_or_else(|e| panic!("{rules}: {e:#}"));
        assert!(
            fake.reads.borrow().contains(&rules_path("wave/one")),
            "{rules}"
        );
        assert_eq!(fake.deletes.borrow().len(), 1, "{rules}");
    }
}

/// `protected` does not report rulesets, and the App bypasses them: a rule type the
/// bot-authority ruleset does not carry marks a branch someone protects.
#[test]
fn refuses_a_ruleset_protected_branch() {
    for kind in ["required_status_checks", "pull_request", "merge_queue"] {
        let mut rules = bot_authority();
        rules.as_array_mut().unwrap().push(rule(kind));
        let text = refused(&ruled(Some(rules)), "wave/one");
        assert!(text.contains("ruleset-protected"), "{kind}: {text}");
        assert!(text.contains(&format!("`{kind}`")), "{kind}: {text}");
    }
    let text = refused(&ruled(Some(json!([{"ruleset_id": 1}]))), "wave/one");
    assert!(text.contains("without a type"), "{text}");
}

/// A second `deletion` rule is a second ruleset restricting deletion.
#[test]
fn refuses_a_second_deletion_rule() {
    let mut rules = bot_authority();
    rules.as_array_mut().unwrap().push(rule("deletion"));
    let text = refused(&ruled(Some(rules)), "wave/one");
    assert!(text.contains("2 rulesets restrict its deletion"), "{text}");
    // From a second ruleset, the same refusal, naming both ids.
    let mut rules = bot_authority();
    rules
        .as_array_mut()
        .unwrap()
        .push(json!({"type": "deletion", "ruleset_id": 7}));
    let text = refused(&ruled(Some(rules)), "wave/one");
    assert!(text.contains("2 rulesets restrict its deletion"), "{text}");
    assert!(text.contains("rulesets 1, 7"), "{text}");
}

/// Each restricting type comes from one and the same ruleset, the bot's: a second
/// ruleset of admitted restricting types, alone or together, is someone protecting the
/// branch, and the refusal names the types and the ruleset ids.
#[test]
fn refuses_restricting_rules_from_a_second_ruleset() {
    for kinds in [
        vec!["creation"],
        vec!["update"],
        vec!["non_fast_forward"],
        vec!["update", "non_fast_forward"],
    ] {
        // Without the bot's own rule of the same type, so the repeat guard does not
        // decide it; the one-ruleset guard must.
        let mut rules: Vec<Value> = bot_authority()
            .as_array()
            .unwrap()
            .iter()
            .filter(|rule| !kinds.contains(&rule["type"].as_str().unwrap()))
            .cloned()
            .collect();
        for kind in &kinds {
            rules.push(json!({"type": kind, "ruleset_id": 9}));
        }
        let text = refused(&ruled(Some(Value::Array(rules))), "wave/one");
        assert!(text.contains("ruleset-protected"), "{kinds:?}: {text}");
        assert!(text.contains("ruleset 1 ("), "{kinds:?}: {text}");
        assert!(
            text.contains(&format!("ruleset 9 ({})", {
                let mut sorted = kinds.clone();
                sorted.sort();
                sorted.join(", ")
            })),
            "{kinds:?}: {text}"
        );
    }
}

/// The bot-authority ruleset carries each restricting type once; any of them twice,
/// even from the same ruleset id, is refused naming the type.
#[test]
fn refuses_a_repeated_restricting_rule() {
    for kind in ["creation", "update", "non_fast_forward"] {
        let mut rules = bot_authority();
        rules.as_array_mut().unwrap().push(rule(kind));
        let text = refused(&ruled(Some(rules)), "wave/one");
        assert!(
            text.contains(&format!("`{kind}` 2 times (rulesets 1, 1)")),
            "{kind}: {text}"
        );
    }
}

/// A rule whose `ruleset_id` is missing or not a positive integer cannot be
/// attributed to a ruleset, whatever its type.
#[test]
fn refuses_an_unattributed_rule() {
    for kind in ["creation", "deletion", "committer_email_pattern"] {
        for id in [
            None,
            Some(json!(0)),
            Some(json!(-1)),
            Some(json!(1.5)),
            Some(json!("1")),
            Some(Value::Null),
        ] {
            let mut entry = json!({"type": kind, "ruleset_source_type": "Organization"});
            if let Some(id) = &id {
                entry["ruleset_id"] = id.clone();
            }
            let rules = bot_authority()
                .as_array()
                .unwrap()
                .iter()
                .filter(|rule| rule["type"] != kind)
                .cloned()
                .chain([entry])
                .collect();
            let text = refused(&ruled(Some(Value::Array(rules))), "wave/one");
            assert!(
                text.contains("did not name the ruleset"),
                "{kind} {id:?}: {text}"
            );
            assert!(text.contains(&format!("`{kind}`")), "{kind} {id:?}: {text}");
        }
    }
}

/// The naming and message patterns may come from any ruleset: GitHub's answer for
/// beyond10x/gates `release/0.1.2` carries the restricting rules from one ruleset and
/// the two email patterns from another, and is deleted.
#[test]
fn deletes_with_patterns_from_other_rulesets() {
    let mut rules: Vec<Value> = ["creation", "update", "deletion", "non_fast_forward"]
        .into_iter()
        .map(|kind| json!({"type": kind, "ruleset_source_type": "Repository", "ruleset_id": 22756851}))
        .collect();
    rules.extend(
        [
            ("commit_author_email_pattern", 22756856),
            ("committer_email_pattern", 22756856),
            ("commit_message_pattern", 5),
            ("committer_name_pattern", 6),
            ("branch_name_pattern", 7),
        ]
        .map(|(kind, id)| json!({"type": kind, "ruleset_source_type": "Repository", "ruleset_id": id})),
    );
    let fake = ruled(Some(Value::Array(rules)));
    delete_remote_branch(&fake, &deletion("wave/one")).unwrap();
    assert_eq!(fake.deletes.borrow().len(), 1);
}

/// A rules answer that is not a JSON array, or a 404, says nothing: refused.
#[test]
fn refuses_unlisted_rulesets() {
    for answer in [
        None,
        Some(Value::Null),
        Some(json!({})),
        Some(json!({"rules": []})),
        Some(json!("deletion")),
    ] {
        let text = refused(&ruled(answer.clone()), "wave/one");
        assert!(
            text.contains("did not list the rulesets"),
            "{answer:?}: {text}"
        );
    }
    // A full page may hide the next one.
    let page = Value::Array((0..100).map(|_| rule("update")).collect());
    let text = refused(&ruled(Some(page)), "wave/one");
    assert!(text.contains("more than one page"), "{text}");
}

/// Run `child` of this test binary with `env`; its `BDB ` lines. The caller's
/// environment reaches the code under test only this way, so no test changes this
/// process's environment.
fn run_child(child: &str, env: &[(&str, &OsStr)]) -> String {
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
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{child}: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
        .lines()
        // libtest prints `test <name> ... ` before the child's first line.
        .filter_map(|line| line.find("BDB ").map(|at| &line[at..]))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A directory standing in for a caller's `GIT_EXEC_PATH`: its `git-upload-pack` and
/// `git-receive-pack` create `marker` and fail.
fn caller_programs(dir: &std::path::Path, marker: &std::path::Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let programs = dir.join("programs");
    std::fs::create_dir_all(&programs).unwrap();
    for name in ["git-upload-pack", "git-receive-pack"] {
        let path = programs.join(name);
        std::fs::write(
            &path,
            format!("#!/bin/sh\ntouch '{}'\nexit 1\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    programs
}

#[test]
#[ignore = "child process entry point: run by the_git_deletion_takes_no_git_variable_of_the_callers"]
fn child_delete_in_the_callers_environment() {
    let remote = std::env::var("BDB_REMOTE").unwrap();
    let tip = std::env::var("BDB_TIP").unwrap();
    let outcome = compare_and_delete_branch(&remote, "wave/one", &tip, None)
        .map_err(|error| format!("{error:#}"));
    println!("BDB {outcome:?}");
}

/// The deletion's scratch repository and push take no `GIT_*` variable of the caller's
/// environment: `GIT_DEFAULT_HASH` would make the scratch repository another kind of
/// repository than the remote, `GIT_EXEC_PATH` would run the caller's
/// `git-receive-pack` and `GIT_NAMESPACE` would address another ref.
#[test]
fn the_git_deletion_takes_no_git_variable_of_the_callers() {
    let (remote, tip) = BareRemote::new();
    let work = tempfile::tempdir().unwrap();
    let marker = work.path().join("caller-program-ran");
    let programs = caller_programs(work.path(), &marker);
    let outcome = run_child(
        "child_delete_in_the_callers_environment",
        &[
            ("BDB_REMOTE", OsStr::new(remote.url())),
            ("BDB_TIP", OsStr::new(&tip)),
            ("GIT_DEFAULT_HASH", OsStr::new("sha256")),
            ("GIT_EXEC_PATH", programs.as_os_str()),
            ("GIT_NAMESPACE", OsStr::new("other")),
        ],
    );
    assert_eq!(outcome, "BDB Ok(Deleted)");
    assert!(!marker.exists(), "the caller's program ran");
    assert_eq!(remote.tip("wave/one"), None);
    assert_eq!(remote.tip("main").as_deref(), Some(tip.as_str()));
}

#[test]
#[ignore = "child process entry point: run by bot_git_runs_in_its_root_with_gits_own_programs"]
fn child_fetch_in_the_callers_environment() {
    let root = std::env::var("BDB_ROOT").unwrap();
    let remote = std::env::var("BDB_REMOTE").unwrap();
    let outcome = bot_git(
        std::path::Path::new(&root),
        &["fetch".to_string(), remote, "refs/heads/main".to_string()],
        None,
    )
    .map_err(|error| format!("{error:#}"));
    println!("BDB {outcome:?}");
}

/// Bot Git runs in the root it is given, with Git's own programs: the caller's
/// `GIT_DIR` would fetch into another repository, and its `GIT_EXEC_PATH` would run
/// the caller's `git-upload-pack` with the bot's environment.
#[test]
fn bot_git_runs_in_its_root_with_gits_own_programs() {
    let (remote, _) = BareRemote::new();
    let root = repository_without_hooks();
    let decoy = repository_without_hooks();
    let work = tempfile::tempdir().unwrap();
    let marker = work.path().join("caller-program-ran");
    let programs = caller_programs(work.path(), &marker);
    let outcome = run_child(
        "child_fetch_in_the_callers_environment",
        &[
            ("BDB_ROOT", root.path().as_os_str()),
            ("BDB_REMOTE", OsStr::new(remote.url())),
            ("GIT_DIR", decoy.path().join(".git").as_os_str()),
            ("GIT_EXEC_PATH", programs.as_os_str()),
        ],
    );
    let fetched = |dir: &tempfile::TempDir| dir.path().join(".git/FETCH_HEAD").exists();
    assert!(
        outcome == "BDB Ok(())" && !marker.exists() && fetched(&root) && !fetched(&decoy),
        "{outcome}: the caller's program ran {}, fetched into the root {}, into the \
         caller's GIT_DIR {}",
        marker.exists(),
        fetched(&root),
        fetched(&decoy)
    );
}
