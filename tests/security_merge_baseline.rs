//! Integrity conformance checks for `b10x-gates bot -- delete-branch` after
//! `story:bot-delete-branch-defaults`: classic protection is now read from
//! `protection.enabled`, so the ruleset answer is the only thing that says whether
//! anyone other than the bot protects a branch, and the repository may now come from
//! the installed hooks' configuration. GitHub is a fake behind
//! `delivery::RemoteBranches`, so no credential is ever minted.
use b10x_gates::{
    bot_args::{delete_branch, delete_branch_repository},
    delivery::{RemoteBranches, delete_remote_branch},
};
use serde_json::{Value, json};
use std::{
    cell::RefCell, collections::HashMap, os::unix::fs::PermissionsExt, path::Path, process::Command,
};

const REPOSITORY: &str = "example/sample";
const TIP: &str = "1111111111111111111111111111111111111111";

#[derive(Default)]
struct Fake {
    answers: HashMap<String, Option<Value>>,
    deletes: RefCell<Vec<String>>,
}

impl RemoteBranches for Fake {
    fn read(&self, path: &str) -> anyhow::Result<Option<Value>> {
        Ok(self
            .answers
            .get(path)
            .unwrap_or_else(|| panic!("unexpected GitHub read {path}"))
            .clone())
    }

    fn delete(&self, path: &str) -> anyhow::Result<()> {
        self.deletes.borrow_mut().push(path.to_string());
        Ok(())
    }
}

fn rule(kind: &str, ruleset: u64, source: &str) -> Value {
    json!({
        "type": kind,
        "ruleset_source_type": source,
        "ruleset_source": REPOSITORY,
        "ruleset_id": ruleset
    })
}

/// The bot-authority rules on a non-default branch, as GitHub answered for
/// beyond10x/gates (ruleset `b10x-bot-branch-authority` plus `b10x-bot-branch-identity`).
fn bot_authority() -> Vec<Value> {
    let mut rules: Vec<Value> = ["creation", "update", "deletion", "non_fast_forward"]
        .into_iter()
        .map(|kind| rule(kind, 1, "Repository"))
        .collect();
    rules.extend(
        ["commit_author_email_pattern", "committer_email_pattern"]
            .into_iter()
            .map(|kind| rule(kind, 2, "Repository")),
    );
    rules
}

/// A merged branch `release/1` with classic protection off (and `protected` true, as
/// GitHub reports for any ruleset-covered branch) whose ruleset rules are `rules`.
fn merged_branch(rules: Vec<Value>) -> Fake {
    let mut answers = HashMap::new();
    answers.insert(
        "/repos/example/sample".to_string(),
        Some(json!({"default_branch": "main"})),
    );
    answers.insert(
        "/repos/example/sample/branches/release/1".to_string(),
        Some(json!({
            "name": "release/1",
            "protected": true,
            "protection": {"enabled": false, "required_status_checks": {"enforcement_level": "off"}},
            "commit": {"sha": TIP}
        })),
    );
    answers.insert(
        format!("/repos/example/sample/compare/{TIP}...main"),
        Some(json!({"status": "ahead", "merge_base_commit": {"sha": TIP}})),
    );
    answers.insert(
        "/repos/example/sample/rules/branches/release/1?per_page=100".to_string(),
        Some(Value::Array(rules)),
    );
    Fake {
        answers,
        ..Fake::default()
    }
}

fn deletion() -> b10x_gates::bot_args::BranchDeletion {
    let args: Vec<String> = ["delete-branch", "release/1"].map(String::from).to_vec();
    delete_branch(&args, Some(REPOSITORY)).unwrap()
}

/// Before this wave, GitHub's top-level `protected` (true under any ruleset) refused
/// every ruleset-covered branch. Now only `rulesets` judges them, and it judges rule
/// *types*: a second ruleset, someone's own "block force pushes" / "restrict updates" on
/// `release/*`, carries only types the bot-authority ruleset also carries, so it is
/// admitted and the branch is deleted. The existing guard already refuses a second
/// `deletion` rule; a second ruleset of any restricting type is the same signal that
/// someone other than the bot protects the branch.
#[test]
fn a_second_ruleset_of_admitted_rule_types_marks_the_branch_protected() {
    let mut rules = bot_authority();
    rules.push(rule("non_fast_forward", 3, "Repository"));
    rules.push(rule("update", 3, "Repository"));
    let fake = merged_branch(rules);
    let outcome = delete_remote_branch(&fake, &deletion());
    assert!(
        outcome.is_err() && fake.deletes.borrow().is_empty(),
        "a branch a second ruleset protects (non_fast_forward + update from ruleset 3) was \
         deleted: {outcome:?}, DELETEs {:?}",
        fake.deletes.borrow()
    );
}

/// Control: the bot-authority rules alone, from the bot's own rulesets, are deleted.
#[test]
fn the_bot_authority_rulesets_alone_are_deleted() {
    let fake = merged_branch(bot_authority());
    assert_eq!(
        delete_remote_branch(&fake, &deletion()).unwrap(),
        format!("deleted release/1 at {TIP}")
    );
}

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args([
            "-c",
            "user.name=example",
            "-c",
            "user.email=example@example.invalid",
        ])
        .args(args)
        .current_dir(root)
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

fn repository() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(dir.path(), &["init", "-q"]);
    dir
}

fn configuration(repository: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "repository": repository,
        "policy": "policy.json",
        "key": "receipt.key",
        "scanner": "gitleaks",
        "previous": {},
        "retired_pre_push_digest": null,
        "installed_version": "0.0.0"
    }))
    .unwrap()
}

fn hooks_directory(root: &Path, mode: u32) -> std::path::PathBuf {
    let directory = root.join(".git/b10x-gates-hooks");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(mode)).unwrap();
    directory
}

fn write_private(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A `config.json` that is a symlink (here to a private file naming another repository)
/// is refused, never followed.
#[test]
fn a_symlinked_hook_configuration_is_refused() {
    let dir = repository();
    let directory = hooks_directory(dir.path(), 0o700);
    let elsewhere = tempfile::tempdir().unwrap();
    let target = elsewhere.path().join("config.json");
    write_private(&target, &configuration("example/other"));
    std::os::unix::fs::symlink(&target, directory.join("config.json")).unwrap();
    let error = delete_branch_repository(dir.path(), None)
        .expect_err("a symlinked configuration was followed");
    assert!(format!("{error:#}").contains("symlink"), "{error:#}");
}

/// A hooks directory other users can write is not trusted, whatever the file's mode.
#[test]
fn a_group_writable_hook_directory_is_refused() {
    let dir = repository();
    let directory = hooks_directory(dir.path(), 0o770);
    write_private(&directory.join("config.json"), &configuration(REPOSITORY));
    let error = delete_branch_repository(dir.path(), None)
        .expect_err("a group-writable hooks directory was trusted");
    assert!(format!("{error:#}").contains("writable"), "{error:#}");
}

/// A configuration that exists but does not parse is refused, never read as absent.
#[test]
fn an_unparsable_hook_configuration_is_refused_not_ignored() {
    let dir = repository();
    let directory = hooks_directory(dir.path(), 0o700);
    write_private(&directory.join("config.json"), b"{\"repository\": 1}");
    let error = delete_branch_repository(dir.path(), None)
        .expect_err("an unparsable configuration was treated as absent");
    assert!(format!("{error:#}").contains("invalid"), "{error:#}");
}

/// A linked worktree reads the configuration of its common directory, as the hooks do.
#[test]
fn a_linked_worktree_resolves_the_common_configuration() {
    let dir = repository();
    git(dir.path(), &["commit", "-q", "--allow-empty", "-m", "root"]);
    let directory = hooks_directory(dir.path(), 0o700);
    write_private(&directory.join("config.json"), &configuration(REPOSITORY));
    let linked = dir.path().join("linked");
    git(
        dir.path(),
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            linked.to_str().unwrap(),
        ],
    );
    assert_eq!(
        delete_branch_repository(&linked, None).unwrap().as_deref(),
        Some(REPOSITORY)
    );
}

/// The binary refuses an untrusted configuration before it reads any bot configuration
/// or mints a credential, and without any policy.
#[test]
fn the_binary_refuses_an_untrusted_configuration_before_any_credential() {
    let dir = repository();
    let directory = hooks_directory(dir.path(), 0o700);
    let config = directory.join("config.json");
    std::fs::write(&config, configuration(REPOSITORY)).unwrap();
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
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
    assert!(stderr.contains("config.json"), "{stderr}");
    assert!(stderr.contains("0644"), "{stderr}");
    assert!(!stderr.contains("absent.json"), "{stderr}");
}
