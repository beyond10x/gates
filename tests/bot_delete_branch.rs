//! `b10x-gates bot [--repository <owner>/<repo>] -- delete-branch <branch>` deletes a
//! remote branch through the REST API as the App, only when its tip is an ancestor of
//! the default branch (`story:bot-delete-branch` and
//! `story:bot-delete-branch-defaults`, modelled as `gates.delivery.DeleteBranch` in
//! `ess/domains/delivery.yaml`). Without `--repository` the repository is the
//! installed hooks' configuration's. Each test is named
//! after the outcome it holds the implementation to. GitHub is a fake behind
//! `delivery::RemoteBranches`, so no credential is ever minted.
use b10x_gates::{
    bot_args::{check, delete_branch, delete_branch_repository},
    delivery::{RemoteBranches, bot_git, delete_remote_branch},
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{HashMap, VecDeque},
    process::Command,
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
            .answer(
                &format!("/repos/example/sample/compare/{TIP}...main"),
                Some(comparison),
            )
            .answer(&rules_path(encoded), Some(bot_authority()))
    }
}

impl RemoteBranches for Fake {
    fn read(&self, path: &str) -> anyhow::Result<Option<Value>> {
        self.reads.borrow_mut().push(path.to_string());
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

    fn delete(&self, path: &str) -> anyhow::Result<()> {
        self.deletes.borrow_mut().push(path.to_string());
        Ok(())
    }
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
            &format!("/repos/example/sample/compare/{TIP}...main"),
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
            vec!["/repos/example/sample/git/refs/heads/wave/one".to_string()],
            "{status}"
        );
        // The branch is read twice: before the comparison and again before the DELETE.
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
    assert_eq!(
        *fake.deletes.borrow(),
        vec!["/repos/example/sample/git/refs/heads/wave/one".to_string()]
    );
}

/// Whatever passes the name rules cannot change the request path: each segment is
/// percent-encoded, `/` separates segments and nothing else does.
#[test]
fn encodes_branch_path_segments() {
    let fake = Fake::merged("wave/a#b%c&d+e", "wave/a%23b%25c%26d%2Be", "ahead");
    delete_remote_branch(&fake, &deletion("wave/a#b%c&d+e")).unwrap();
    assert_eq!(
        *fake.deletes.borrow(),
        vec!["/repos/example/sample/git/refs/heads/wave/a%23b%25c%26d%2Be".to_string()]
    );
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
    assert_eq!(
        *fake.deletes.borrow(),
        vec!["/repos/example/sample/git/refs/heads/wave/one".to_string()]
    );
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

/// `delete-branch` is not a Git command: the library's Git route refuses it before Git.
#[test]
fn library_git_never_runs_delete_branch() {
    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        "{:#}",
        bot_git(dir.path(), &args("delete-branch wave/one"), None).unwrap_err()
    );
    assert!(text.contains("REST API"), "{text}");
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
