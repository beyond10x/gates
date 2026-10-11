//! Security conformance of the bot verbs against `design:bot-verbs` and its owner
//! decision: every created commit is the bot's and holds only what the verb names, no
//! repository-chosen command runs during an integration, and configuration from the
//! caller's environment cannot do what the `-c` refusal forbids in argv. Git runs in a
//! temporary repository with a neutral identity through the token-free
//! `delivery::bot_git`, so no credential is ever minted.
use b10x_gates::delivery::bot_git;
use std::{fs, path::Path, process::Command};

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

fn init() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    git(
        dir.path(),
        &["-c", "init.templateDir=", "init", "-q", "-b", "main"],
    );
    dir
}

fn bot(dir: &Path, line: &str) -> anyhow::Result<()> {
    bot_git(dir, &args(line), None)
}

#[cfg(unix)]
fn marker_hook(dir: &Path, hook: &str) {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(".git/hooks").join(hook);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, format!("#!/bin/sh\ntouch .git/{hook}-ran\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The owner decision adds `merge` and `revert` "with the refusals listed above (...,
/// and a merge driver named in `.git/config`)", and the design gives `revert` "the same
/// refusals as `merge`". A revert is a three-way merge, so Git runs the configured
/// driver for a path both sides changed; the bot must refuse before it runs.
#[test]
fn revert_refuses_a_configured_merge_driver() {
    let dir = init();
    let path = dir.path();
    commit_file(
        path,
        ".gitattributes",
        "base.txt merge=probe\n",
        "attributes",
    );
    commit_file(path, "base.txt", "one\ntwo\nthree\nfour\nfive\n", "base");
    commit_file(
        path,
        "base.txt",
        "ONE\ntwo\nthree\nfour\nfive\n",
        "first line",
    );
    commit_file(
        path,
        "base.txt",
        "ONE\ntwo\nthree\nfour\nFIVE\n",
        "last line",
    );
    git(
        path,
        &["config", "merge.probe.driver", "touch .git/driver-ran"],
    );
    let before = out(path, &["rev-parse", "HEAD"]);
    let result = bot(path, "revert HEAD~1");
    let ran = path.join(".git/driver-ran").exists();
    let text = match result {
        Ok(()) => "the revert ran".to_string(),
        Err(error) => format!("{error:#}"),
    };
    assert!(
        !ran,
        "the configured merge driver ran during a bot revert: {text}"
    );
    assert!(text.contains("merge driver"), "{text}");
    assert!(text.contains("probe"), "{text}");
    assert_eq!(out(path, &["rev-parse", "HEAD"]), before);
}

/// `git revert --no-commit` reverts against the index as it stands, so a change staged
/// before the call is folded into the bot's `Revert "…"` commit. The accepted outcome
/// is one commit reverting the target: either refuse a dirty index (as `merge` does) or
/// commit nothing but the reversion.
#[test]
fn revert_commits_only_the_reversion() {
    let dir = init();
    let path = dir.path();
    commit_file(path, "base.txt", "base\n", "base");
    commit_file(path, "target.txt", "target\n", "target");
    fs::write(path.join("unrelated.txt"), "unrelated\n").unwrap();
    git(path, &["add", "unrelated.txt"]);
    let before = out(path, &["rev-parse", "HEAD"]);
    match bot(path, "revert HEAD") {
        Err(error) => {
            // Refusing a dirty index is a conforming answer; nothing was committed.
            assert_eq!(out(path, &["rev-parse", "HEAD"]), before, "{error:#}");
        }
        Ok(()) => {
            let changed = out(path, &["show", "--name-only", "--format=", "HEAD"]);
            assert_eq!(
                changed, "target.txt",
                "the bot's Revert commit carries changes it did not revert"
            );
        }
    }
}

/// The bot refuses `-c` and `--config-env` in argv because they can move the hooks the
/// bot's commit and push run. `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT` carry the
/// same configuration through the environment; `merge` and `revert` drop them, and so
/// must `commit` and `push`. The test re-runs itself with each variable set, so no
/// other test shares that environment.
#[cfg(unix)]
#[test]
fn commit_and_push_ignore_configuration_from_the_environment() {
    const NAME: &str = "commit_and_push_ignore_configuration_from_the_environment";
    if std::env::var_os("B10X_GATES_TEST_ENVIRONMENT").is_none() {
        for variable in ["GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"] {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", NAME, "--test-threads=1", "--nocapture"])
                .env("B10X_GATES_TEST_ENVIRONMENT", "1");
            if variable == "GIT_CONFIG_PARAMETERS" {
                command.env(variable, "'core.hookspath'='/nonexistent'");
            } else {
                command
                    .env(variable, "1")
                    .env("GIT_CONFIG_KEY_0", "core.hooksPath")
                    .env("GIT_CONFIG_VALUE_0", "/nonexistent");
            }
            let output = command.output().unwrap();
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "{variable}: {stdout}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                stdout.contains("1 passed"),
                "{variable}: the inner run did not run the test"
            );
        }
        return;
    }
    let remote = tempfile::tempdir().unwrap();
    let status = Command::new("git")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_COUNT")
        .args(["init", "-q", "--bare"])
        .arg(remote.path())
        .status()
        .unwrap();
    assert!(status.success());
    let dir = init();
    let path = dir.path();
    commit_file(path, "base.txt", "base\n", "base");
    marker_hook(path, "pre-commit");
    marker_hook(path, "pre-push");
    fs::write(path.join("change.txt"), "change\n").unwrap();
    git(path, &["add", "change.txt"]);
    bot(path, "commit -q -m change").unwrap();
    let remote = remote.path().to_str().unwrap();
    bot(path, &format!("push -q {remote} main")).unwrap();
    let skipped: Vec<&str> = ["pre-commit", "pre-push"]
        .into_iter()
        .filter(|hook| !path.join(format!(".git/{hook}-ran")).exists())
        .collect();
    assert!(
        skipped.is_empty(),
        "the bot skipped the repository's {skipped:?} hook(s): configuration from the \
         environment moved core.hooksPath"
    );
}

/// Refusals carry no private data. A local filesystem path holds the user's home
/// directory, which the `personal-paths` rule refuses wherever it is published; the
/// refusal names the cause (`.git/config` includes other configuration), not the path.
#[test]
fn merge_refusal_names_no_local_path() {
    let dir = init();
    let path = dir.path();
    commit_file(path, "base.txt", "base\n", "base");
    git(path, &["branch", "feature"]);
    git(path, &["config", "include.path", "elsewhere.config"]);
    let text = match bot(path, "merge feature") {
        Ok(()) => panic!("the merge ran with an include in .git/config"),
        Err(error) => format!("{error:#}"),
    };
    assert!(text.contains("include"), "{text}");
    let root = fs::canonicalize(path).unwrap();
    for local in [path.to_str().unwrap(), root.to_str().unwrap()] {
        assert!(
            !text.contains(local),
            "the refusal carries the local path {local}: {text}"
        );
    }
}
