//! Adversary pass on `b10x-gates bot -- merge|revert|delete-branch`
//! (`story:bot-merge-revert`, `story:bot-delete-branch`). Each test asserts what the
//! story's contract promises; a red test is a break. Git runs in a temporary
//! repository with the neutral identity `example`, through the token-free
//! `delivery::bot_git`; GitHub is a fake behind `delivery::RemoteBranches`. No
//! credential is ever minted.
use b10x_gates::{
    bot_args::delete_branch,
    delivery::{RemoteBranches, api_path_admitted, bot_git, delete_remote_branch},
};
use serde_json::{Value, json};
use std::{cell::RefCell, fs, path::Path, process::Command};

fn args(line: &str) -> Vec<String> {
    line.split_whitespace().map(String::from).collect()
}

fn base(dir: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(dir)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .args([
            "-c",
            "user.name=example",
            "-c",
            "user.email=example@example.invalid",
            "-c",
            "core.editor=false",
        ]);
    command
}

fn git(dir: &Path, args: &[&str]) {
    let status = base(dir).args(args).status().unwrap();
    assert!(status.success(), "git {args:?}");
}

fn out(dir: &Path, args: &[&str]) -> String {
    let output = base(dir).args(args).output().unwrap();
    assert!(output.status.success(), "git {args:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

fn commit_file(dir: &Path, path: &str, content: &str, message: &str) {
    fs::write(dir.join(path), content).unwrap();
    git(dir, &["add", path]);
    git(dir, &["commit", "-q", "-m", message]);
}

/// `main`: base, one, two. `feature` and `other` each one commit ahead of base.
fn repository() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path();
    git(
        path,
        &["-c", "init.templateDir=", "init", "-q", "-b", "main"],
    );
    commit_file(path, "base.txt", "base\n", "base");
    git(path, &["switch", "-q", "-c", "feature"]);
    commit_file(path, "feature.txt", "feature\n", "add feature");
    git(path, &["switch", "-q", "-c", "other", "main"]);
    commit_file(path, "other.txt", "other\n", "add other");
    git(path, &["switch", "-q", "main"]);
    commit_file(path, "one.txt", "one\n", "one");
    commit_file(path, "two.txt", "two\n", "two");
    dir
}

fn bot(dir: &Path, line: &str) -> anyhow::Result<()> {
    bot_git(dir, &args(line), None)
}

fn commits(dir: &Path) -> usize {
    out(dir, &["rev-list", "--count", "HEAD"]).parse().unwrap()
}

/// The story admits exactly one revision to `revert`: "no revert of a range". `git
/// revert` hands everything its option parser does not know to the revision walker,
/// and `--do-walk` turns the single revision into its whole ancestry.
#[test]
fn revert_reverts_only_its_one_revision_not_its_ancestry() {
    let dir = repository();
    let path = dir.path();
    let before = commits(path);
    let result = bot(path, "revert --do-walk HEAD");
    let added = commits(path) - before;
    assert!(
        added <= 1,
        "`revert --do-walk HEAD` created {added} commits ({result:?})"
    );
    assert!(
        path.join("one.txt").exists() && path.join("base.txt").exists(),
        "`revert --do-walk HEAD` reverted more than HEAD ({result:?})"
    );
}

/// A revision walker option that names refs adds revisions the argument check never
/// counts: `--tags` with the tag `v1` on `one` reverts `one` as well as `HEAD`.
#[test]
fn revert_takes_no_second_revision_from_a_ref_option() {
    let dir = repository();
    let path = dir.path();
    git(path, &["tag", "v1", "main~1"]);
    let before = commits(path);
    let result = bot(path, "revert --tags HEAD");
    let added = commits(path) - before;
    assert!(
        added <= 1,
        "`revert --tags HEAD` created {added} commits ({result:?})"
    );
    assert!(
        path.join("one.txt").exists(),
        "`revert --tags HEAD` reverted the tagged commit too ({result:?})"
    );
}

/// The story admits exactly one revision to `merge`: "no octopus merge". `git merge
/// FETCH_HEAD` merges every for-merge line of `.git/FETCH_HEAD`, which a plain
/// `fetch` of two branches writes.
#[test]
fn merge_of_fetch_head_is_never_an_octopus() {
    let dir = repository();
    let path = dir.path();
    let feature = out(path, &["rev-parse", "feature"]);
    let other = out(path, &["rev-parse", "other"]);
    fs::write(
        path.join(".git/FETCH_HEAD"),
        format!("{feature}\t\tbranch 'feature' of example\n{other}\t\tbranch 'other' of example\n"),
    )
    .unwrap();
    let result = bot(path, "merge FETCH_HEAD");
    let parents = out(path, &["log", "-1", "--format=%P", "HEAD"])
        .split_whitespace()
        .count();
    assert!(
        parents <= 2,
        "`merge FETCH_HEAD` committed an octopus with {parents} parents ({result:?})"
    );
}

/// The bot refuses `-c core.hooksPath=…` and `--config-env` for every verb ("bot
/// delivery cannot bypass hooks or inject Git configuration"), yet `commit` and
/// `push` still read the same setting from the caller's `GIT_CONFIG_PARAMETERS` or
/// `GIT_CONFIG_COUNT`. A refusing `pre-commit` and `pre-push` hook must still stop
/// them. The test re-runs itself with the variables set, so no other test shares
/// that environment; the inner run without them is the control.
#[cfg(unix)]
#[test]
fn commit_and_push_run_the_hooks_whatever_the_environment() {
    use std::os::unix::fs::PermissionsExt;
    const NAME: &str = "commit_and_push_run_the_hooks_whatever_the_environment";
    if std::env::var_os("B10X_GATES_ADVERSARY_ENVIRONMENT").is_none() {
        let injected: [(&str, &[(&str, &str)]); 3] = [
            ("control", &[]),
            (
                "GIT_CONFIG_PARAMETERS",
                &[("GIT_CONFIG_PARAMETERS", "'core.hookspath'='/nonexistent'")],
            ),
            (
                "GIT_CONFIG_COUNT",
                &[
                    ("GIT_CONFIG_COUNT", "1"),
                    ("GIT_CONFIG_KEY_0", "core.hooksPath"),
                    ("GIT_CONFIG_VALUE_0", "/nonexistent"),
                ],
            ),
        ];
        let mut failures = Vec::new();
        for (label, variables) in injected {
            let output = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", NAME, "--test-threads=1"])
                .env("B10X_GATES_ADVERSARY_ENVIRONMENT", "1")
                .envs(variables.iter().copied())
                .output()
                .unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                stdout.contains("1 passed") || stdout.contains("1 failed"),
                "{label}: the inner run did not run the test"
            );
            if !output.status.success() {
                let reason = stdout
                    .lines()
                    .find(|l| l.contains("did not run"))
                    .unwrap_or("")
                    .to_string();
                failures.push(format!("{label}: {reason}"));
            }
        }
        assert!(failures.is_empty(), "{failures:#?}");
        return;
    }
    let dir = repository();
    let path = dir.path();
    let hooks = path.join(".git/hooks");
    fs::create_dir_all(&hooks).unwrap();
    for name in ["pre-commit", "pre-push"] {
        let hook = hooks.join(name);
        fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    }
    fs::write(path.join("staged.txt"), "staged\n").unwrap();
    git(path, &["add", "staged.txt"]);
    let before = out(path, &["rev-parse", "HEAD"]);
    let committed = bot(path, "commit -q -m staged");
    let commit_held = committed.is_err() && out(path, &["rev-parse", "HEAD"]) == before;

    let remote = tempfile::tempdir().unwrap();
    git(remote.path(), &["init", "-q", "--bare"]);
    let pushed = bot_git(
        path,
        &[
            "push".to_string(),
            "-q".to_string(),
            remote.path().display().to_string(),
            "main".to_string(),
        ],
        None,
    );
    let mut broken = Vec::new();
    if !commit_held {
        broken.push("pre-commit");
    }
    if pushed.is_ok() {
        broken.push("pre-push");
    }
    assert!(
        broken.is_empty(),
        "the refusing hooks {broken:?} did not run: the bot commit or push succeeded"
    );
}

// --- delete-branch ---------------------------------------------------------------

const TIP: &str = "1111111111111111111111111111111111111111";

#[derive(Default)]
struct Fake {
    answers: RefCell<Vec<(String, Option<Value>)>>,
    reads: RefCell<Vec<String>>,
    deletes: RefCell<Vec<String>>,
}

impl Fake {
    fn answer(self, path: &str, value: Option<Value>) -> Self {
        self.answers.borrow_mut().push((path.to_string(), value));
        self
    }
}

impl RemoteBranches for Fake {
    fn read(&self, path: &str) -> anyhow::Result<Option<Value>> {
        // The real client's path guard: a path `Github::api_response` refuses is refused here.
        anyhow::ensure!(api_path_admitted(path), "invalid GitHub API path");
        self.reads.borrow_mut().push(path.to_string());
        let answers = self.answers.borrow();
        let (_, value) = answers
            .iter()
            .find(|(p, _)| p == path)
            .unwrap_or_else(|| panic!("unexpected GitHub read {path}"));
        Ok(value.clone())
    }

    fn delete(&self, path: &str) -> anyhow::Result<()> {
        anyhow::ensure!(api_path_admitted(path), "invalid GitHub API path");
        self.deletes.borrow_mut().push(path.to_string());
        Ok(())
    }
}

fn deletion(branch: &str) -> anyhow::Result<b10x_gates::bot_args::BranchDeletion> {
    delete_branch(
        &args(&format!("delete-branch {branch}")),
        Some("example/sample"),
    )
}

/// A name that already holds a percent escape is sent with the `%` itself escaped,
/// so GitHub decodes it once to the literal name and never to `x/main`.
#[test]
fn percent_escapes_in_a_branch_name_are_never_decoded_twice() {
    let fake = Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": "main"})),
        )
        .answer("/repos/example/sample/branches/x%252Fmain", None);
    let deletion = deletion("x%2Fmain").unwrap();
    let error = delete_remote_branch(&fake, &deletion).unwrap_err();
    assert!(format!("{error:#}").contains("does not exist"), "{error:#}");
    assert!(fake.deletes.borrow().is_empty());
}

/// Answer shapes that do not say what the guard needs are refusals, never defaults:
/// no `protection.enabled`, a `protection.enabled` that is a string, a missing merge
/// base, and a comparison that names the right status for another base.
#[test]
fn ambiguous_github_answers_refuse_the_deletion() {
    let repo = ("/repos/example/sample", json!({"default_branch": "main"}));
    let cases = [
        (json!({"name": "done", "commit": {"sha": TIP}}), None),
        (
            json!({"name": "done", "protected": false, "protection": {"enabled": "false"}, "commit": {"sha": TIP}}),
            None,
        ),
        (
            json!({"name": "done", "protected": true, "protection": {"enabled": false}, "commit": {"sha": TIP}}),
            Some(json!({"status": "ahead"})),
        ),
        (
            json!({"name": "done", "protected": true, "protection": {"enabled": false}, "commit": {"sha": TIP}}),
            Some(json!({
                "status": "identical",
                "merge_base_commit": {"sha": "2222222222222222222222222222222222222222"}
            })),
        ),
    ];
    for (branch, comparison) in cases {
        let fake = Fake::default()
            .answer(repo.0, Some(repo.1.clone()))
            .answer("/repos/example/sample/branches/done", Some(branch.clone()))
            .answer(
                &format!("/repos/example/sample/compare/{TIP}%2E%2E%2Emain"),
                comparison.clone(),
            );
        let result = delete_remote_branch(&fake, &deletion("done").unwrap());
        assert!(result.is_err(), "{branch} / {comparison:?} was deleted");
        assert!(fake.deletes.borrow().is_empty());
    }
}

/// `refs/heads/<default>`, `HEAD` and `@` never reach a DELETE of the default branch.
#[test]
fn spellings_of_the_default_branch_are_refused() {
    for name in ["refs/heads/main", "HEAD", "@"] {
        let Ok(deletion) = deletion(name) else {
            continue;
        };
        // GitHub answers `HEAD` with the branch it resolves to.
        let fake = Fake::default()
            .answer(
                "/repos/example/sample",
                Some(json!({"default_branch": "main"})),
            )
            .answer(
                &format!("/repos/example/sample/branches/{name}"),
                Some(json!({"name": "main", "protected": true, "protection": {"enabled": false}, "commit": {"sha": TIP}})),
            )
            .answer(
                &format!("/repos/example/sample/compare/{TIP}%2E%2E%2Emain"),
                Some(json!({"status": "identical", "merge_base_commit": {"sha": TIP}})),
            );
        assert!(
            delete_remote_branch(&fake, &deletion).is_err(),
            "`{name}` was deleted"
        );
        assert!(fake.deletes.borrow().is_empty(), "`{name}`");
    }
}
