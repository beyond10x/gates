//! `b10x-gates bot -- merge` and `bot -- revert` run Git's no-commit form in the bot
//! environment and commit the result as the bot (`story:bot-merge-revert`, modelled
//! as `gates.delivery.Merge` and `gates.delivery.Revert` in `ess/domains/delivery.yaml`).
//! Each test is named after the outcome it holds the implementation to. Git runs in a
//! temporary repository with a neutral identity, through the token-free
//! `delivery::bot_git`, so no credential is ever minted.
use b10x_gates::{BOT_EMAIL, BOT_NAME, bot_args::check, delivery::bot_git};
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

fn exists(dir: &Path, reference: &str) -> bool {
    base(dir)
        .args(["rev-parse", "-q", "--verify", reference])
        .stdout(std::process::Stdio::null())
        .status()
        .unwrap()
        .success()
}

fn commit_file(dir: &Path, path: &str, content: &str, message: &str) {
    fs::write(dir.join(path), content).unwrap();
    git(dir, &["add", path]);
    git(dir, &["commit", "-q", "-m", message]);
}

/// `main` with a base commit, and `feature` one commit ahead of the base, with
/// `main` one other commit ahead too, so the merge is a true merge.
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
    git(path, &["switch", "-q", "main"]);
    commit_file(path, "main.txt", "main\n", "advance main");
    dir
}

/// `feature` and `main` change the same line of `base.txt`.
fn conflicting_repository() -> tempfile::TempDir {
    let dir = repository();
    let path = dir.path();
    git(path, &["switch", "-q", "feature"]);
    commit_file(path, "base.txt", "feature side\n", "feature side");
    git(path, &["switch", "-q", "main"]);
    commit_file(path, "base.txt", "main side\n", "main side");
    dir
}

fn bot(dir: &Path, line: &str) -> anyhow::Result<()> {
    bot_git(dir, &args(line), None)
}

fn refusal(dir: &Path, line: &str) -> String {
    match bot(dir, line) {
        Ok(()) => panic!("`{line}` ran"),
        Err(error) => format!("{error:#}"),
    }
}

fn identity(dir: &Path, revision: &str) -> String {
    out(dir, &["log", "-1", "--format=%an|%ae|%cn|%ce", revision])
}

fn bot_identity() -> String {
    format!("{BOT_NAME}|{BOT_EMAIL}|{BOT_NAME}|{BOT_EMAIL}")
}

#[test]
fn merge_creates_one_bot_commit_with_two_parents() {
    let dir = repository();
    let path = dir.path();
    let main = out(path, &["rev-parse", "main"]);
    let feature = out(path, &["rev-parse", "feature"]);
    bot(path, "merge feature").unwrap();
    assert_eq!(out(path, &["rev-parse", "HEAD^1"]), main);
    assert_eq!(out(path, &["rev-parse", "HEAD^2"]), feature);
    assert_eq!(out(path, &["rev-list", "--count", "--merges", "HEAD"]), "1");
    assert_eq!(identity(path, "HEAD"), bot_identity());
    assert!(!exists(path, "MERGE_HEAD"));
    assert!(path.join("feature.txt").exists());
}

#[test]
fn merge_keeps_the_prepared_message_unless_one_is_given() {
    let dir = repository();
    bot(dir.path(), "merge feature").unwrap();
    assert_eq!(
        out(dir.path(), &["log", "-1", "--format=%s"]),
        "Merge branch 'feature'"
    );

    let dir = repository();
    let line = ["merge", "-m", "join the feature line", "feature"].map(String::from);
    bot_git(dir.path(), &line, None).unwrap();
    assert_eq!(
        out(dir.path(), &["log", "-1", "--format=%B"]),
        "join the feature line"
    );
    assert_eq!(out(dir.path(), &["rev-list", "--count", "HEAD^@"]), "3");

    let dir = repository();
    let message = dir.path().join(".git").join("message.txt");
    fs::write(&message, "from a file\n\nwith a body\n").unwrap();
    let line = ["merge", "-F", ".git/message.txt", "feature"].map(String::from);
    bot_git(dir.path(), &line, None).unwrap();
    assert_eq!(
        out(dir.path(), &["log", "-1", "--format=%B"]),
        "from a file\n\nwith a body"
    );
    assert_eq!(identity(dir.path(), "HEAD"), bot_identity());
}

#[cfg(unix)]
#[test]
fn merge_commit_runs_the_commit_hooks() {
    use std::os::unix::fs::PermissionsExt;
    let dir = repository();
    let path = dir.path();
    let hooks = path.join(".git").join("hooks");
    fs::create_dir_all(&hooks).unwrap();
    for name in ["pre-commit", "commit-msg"] {
        let hook = hooks.join(name);
        fs::write(&hook, format!("#!/bin/sh\ntouch .git/{name}-ran\n")).unwrap();
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    }
    bot(path, "merge feature").unwrap();
    assert!(path.join(".git/pre-commit-ran").exists());
    assert!(path.join(".git/commit-msg-ran").exists());

    // A refusing pre-commit hook stops the commit: the merge stays in progress.
    let dir = repository();
    let path = dir.path();
    let hook = path.join(".git/hooks/pre-commit");
    fs::create_dir_all(hook.parent().unwrap()).unwrap();
    fs::write(&hook, "#!/bin/sh\nexit 1\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    let before = out(path, &["rev-parse", "HEAD"]);
    refusal(path, "merge feature");
    assert_eq!(out(path, &["rev-parse", "HEAD"]), before);
}

#[test]
fn revert_creates_one_bot_commit_reverting_the_target() {
    let dir = repository();
    let path = dir.path();
    let before = out(path, &["rev-parse", "HEAD"]);
    bot(path, "revert HEAD").unwrap();
    assert_eq!(out(path, &["rev-parse", "HEAD^"]), before);
    assert_eq!(
        out(path, &["log", "-1", "--format=%s"]),
        "Revert \"advance main\""
    );
    assert_eq!(identity(path, "HEAD"), bot_identity());
    assert!(!path.join("main.txt").exists());

    // A merge commit is reverted against its first parent with `-m 1`.
    let dir = repository();
    let path = dir.path();
    git(path, &["merge", "-q", "--no-ff", "--no-edit", "feature"]);
    assert!(path.join("feature.txt").exists());
    bot(path, "revert -m 1 HEAD").unwrap();
    assert!(!path.join("feature.txt").exists());
    assert!(path.join("main.txt").exists());
    assert_eq!(identity(path, "HEAD"), bot_identity());
    assert!(
        out(path, &["log", "-1", "--format=%s"]).starts_with("Revert \"Merge branch 'feature'\""),
    );
}

/// Each forbidden option, each long one also by a prefix Git accepts, and as part
/// of a short cluster. The refusal names the option and runs no Git.
fn forbidden(verb: &str) -> Vec<(String, &'static str)> {
    let cases: [(&str, &str); 37] = [
        ("-s ours", "-s"),
        ("-sours", "-s"),
        ("-qs ours", "-s"),
        ("--strategy ours", "--strategy"),
        ("--strategy=ours", "--strategy"),
        ("--strat=ours", "--strat"),
        ("-X ours", "-X"),
        ("-Xours", "-X"),
        ("--strategy-option ours", "--strategy-option"),
        ("--strategy-o=ours", "--strategy-o"),
        ("--squash", "--squash"),
        ("--squ", "--squ"),
        ("--ff-only", "--ff-only"),
        ("--ff-o", "--ff-o"),
        ("--ff", "--ff"),
        ("--allow-unrelated-histories", "--allow-unrelated-histories"),
        ("--allow-u", "--allow-u"),
        ("--commit", "--commit"),
        ("--comm", "--comm"),
        ("-e", "-e"),
        ("--edit", "--edit"),
        ("--ed", "--ed"),
        ("--continue", "--continue"),
        ("--cont", "--cont"),
        ("--abort", "--abort"),
        ("--ab", "--ab"),
        ("--quit", "--quit"),
        ("--qui", "--qui"),
        ("--skip", "--skip"),
        ("--sk", "--sk"),
        ("--no-verify", "--no-verify"),
        ("--no-verif", "--no-verif"),
        ("-n", "-n"),
        ("-c core.hooksPath=x", "-c"),
        ("--config-env=core.hooksPath=X", "--config-env"),
        ("--config-e=core.hooksPath=X", "--config-e"),
        ("--exec=elsewhere", "--exec"),
    ];
    cases
        .iter()
        .map(|(option, named)| (format!("{verb} {option} HEAD"), *named))
        .chain([(format!("{verb} --ex=elsewhere HEAD"), "--ex")])
        .collect()
}

fn refuses_each_forbidden_option(verb: &str) {
    let dir = repository();
    let path = dir.path();
    let before = out(path, &["rev-parse", "HEAD"]);
    for (line, named) in forbidden(verb) {
        let text = match check(&args(&line), None) {
            Ok(()) => panic!("`{line}` passed the bot argument check"),
            Err(error) => format!("{error:#}"),
        };
        assert!(text.contains(&format!("`{named}`")), "{line}: {text}");
        let text = refusal(path, &line);
        assert!(!text.contains("failed (exit"), "{line} reached Git: {text}");
        assert_eq!(out(path, &["rev-parse", "HEAD"]), before, "{line}");
        assert!(!exists(path, "MERGE_HEAD"), "{line}");
    }
}

#[test]
fn merge_refuses_each_forbidden_option() {
    refuses_each_forbidden_option("merge");
}

#[test]
fn revert_refuses_each_forbidden_option() {
    refuses_each_forbidden_option("revert");
}

/// Options that are not forbidden still pass: a full long name is not a prefix of
/// a forbidden one, and a letter inside a value is part of the value.
#[test]
fn merge_and_revert_admit_their_other_options() {
    for line in [
        "merge feature",
        "merge --no-ff feature",
        "merge --quiet --stat feature",
        "merge --compact-summary feature",
        "merge -m snapshot feature",
        "merge -msnapshot feature",
        "merge -F - feature",
        "merge --message=n feature",
        "merge --no-edit feature",
        "revert HEAD",
        "revert -m 1 HEAD",
        "revert --mainline 1 HEAD",
        "revert --no-edit HEAD",
    ] {
        check(&args(line), None).unwrap_or_else(|e| panic!("`{line}` refused: {e:#}"));
    }
}

#[test]
fn merge_refuses_a_configured_merge_driver() {
    let dir = repository();
    let path = dir.path();
    git(
        path,
        &["config", "merge.union-lines.driver", "true %O %A %B"],
    );
    let before = out(path, &["rev-parse", "HEAD"]);
    let text = refusal(path, "merge feature");
    assert!(text.contains("merge driver"), "{text}");
    assert!(text.contains("union-lines"), "{text}");
    assert_eq!(out(path, &["rev-parse", "HEAD"]), before);
    assert!(!exists(path, "MERGE_HEAD"));

    // A driver declared only for this worktree is refused the same way.
    let dir = repository();
    let path = dir.path();
    git(path, &["config", "extensions.worktreeConfig", "true"]);
    git(
        path,
        &["config", "--worktree", "merge.Worktree-Only.driver", "true"],
    );
    let text = refusal(path, "merge feature");
    assert!(text.contains("Worktree-Only"), "{text}");
    assert!(!exists(path, "MERGE_HEAD"));

    // Configuration another file includes cannot be read as data: refused.
    let dir = repository();
    let path = dir.path();
    git(path, &["config", "include.path", "elsewhere.config"]);
    let text = refusal(path, "merge feature");
    assert!(text.contains("include"), "{text}");
    assert!(!exists(path, "MERGE_HEAD"));
}

/// Configuration from the caller's environment cannot name a merge driver the
/// `.git/config` check never sees, nor move the hooks the bot commit runs. The test
/// re-runs itself with the variables set, so no other test shares that environment.
#[cfg(unix)]
#[test]
fn merge_ignores_configuration_from_the_environment() {
    use std::os::unix::fs::PermissionsExt;
    const NAME: &str = "merge_ignores_configuration_from_the_environment";
    if std::env::var_os("B10X_GATES_TEST_ENVIRONMENT").is_none() {
        let injected = [
            (
                "GIT_CONFIG_PARAMETERS",
                "'merge.injected.driver'='touch .git/driver-ran' 'core.hookspath'='/nonexistent'",
            ),
            ("GIT_CONFIG_COUNT", "2"),
        ];
        for (variable, value) in injected {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", NAME, "--test-threads=1"])
                .env("B10X_GATES_TEST_ENVIRONMENT", "1")
                .env(variable, value);
            if variable == "GIT_CONFIG_COUNT" {
                command
                    .env("GIT_CONFIG_KEY_0", "merge.injected.driver")
                    .env("GIT_CONFIG_VALUE_0", "touch .git/driver-ran")
                    .env("GIT_CONFIG_KEY_1", "core.hooksPath")
                    .env("GIT_CONFIG_VALUE_1", "/nonexistent");
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "{variable}: {}",
                String::from_utf8_lossy(&output.stdout)
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains("1 passed"),
                "{variable}: the inner run did not run the test"
            );
        }
        return;
    }
    // A merge whose conflict the injected driver would resolve: it stays a conflict.
    let dir = conflicting_repository();
    let path = dir.path();
    commit_file(
        path,
        ".gitattributes",
        "base.txt merge=injected\n",
        "attributes",
    );
    let text = refusal(path, "merge feature");
    assert!(text.contains("conflict"), "{text}");
    assert!(!path.join(".git/driver-ran").exists());

    // The bot commit runs the repository's hooks, not the injected hook path.
    let dir = repository();
    let path = dir.path();
    let hook = path.join(".git/hooks/pre-commit");
    fs::create_dir_all(hook.parent().unwrap()).unwrap();
    fs::write(&hook, "#!/bin/sh\ntouch .git/pre-commit-ran\n").unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    bot(path, "merge feature").unwrap();
    assert!(path.join(".git/pre-commit-ran").exists());
}

#[test]
fn merge_refuses_when_an_operation_is_in_progress() {
    let dir = conflicting_repository();
    let path = dir.path();
    git(path, &["switch", "-q", "-c", "other", "main~1"]);
    commit_file(path, "base.txt", "other side\n", "other side");
    let status = base(path)
        .args(["merge", "-q", "--no-edit", "feature"])
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(exists(path, "MERGE_HEAD"));
    let before = out(path, &["rev-parse", "HEAD"]);
    let text = refusal(path, "merge main");
    assert!(text.contains("in progress"), "{text}");
    assert!(text.contains("merge"), "{text}");
    assert_eq!(out(path, &["rev-parse", "HEAD"]), before);
    assert_eq!(
        out(path, &["rev-parse", "MERGE_HEAD"]),
        out(path, &["rev-parse", "feature"])
    );
}

#[test]
fn revert_refuses_when_an_operation_is_in_progress() {
    let dir = conflicting_repository();
    let path = dir.path();
    let status = base(path)
        .args(["cherry-pick", "feature"])
        .status()
        .unwrap();
    assert!(!status.success());
    assert!(exists(path, "CHERRY_PICK_HEAD"));
    let before = out(path, &["rev-parse", "HEAD"]);
    let text = refusal(path, "revert HEAD~1");
    assert!(text.contains("cherry-pick in progress"), "{text}");
    assert_eq!(out(path, &["rev-parse", "HEAD"]), before);
}

#[test]
fn merge_conflict_prints_the_finish_route_and_leaves_the_index() {
    let dir = conflicting_repository();
    let path = dir.path();
    let before = out(path, &["rev-parse", "HEAD"]);
    let text = refusal(path, "merge feature");
    assert!(text.contains("conflict"), "{text}");
    assert!(text.contains("git add"), "{text}");
    assert!(text.contains("b10x-gates bot -- commit -F -"), "{text}");
    assert!(text.contains("git merge --abort"), "{text}");
    assert_eq!(out(path, &["rev-parse", "HEAD"]), before);
    assert!(exists(path, "MERGE_HEAD"));
    assert!(!out(path, &["ls-files", "-u"]).is_empty());
}

#[test]
fn revert_conflict_prints_the_finish_route_and_leaves_the_index() {
    let dir = repository();
    let path = dir.path();
    commit_file(path, "base.txt", "first change\n", "first change");
    commit_file(path, "base.txt", "second change\n", "second change");
    let before = out(path, &["rev-parse", "HEAD"]);
    let text = refusal(path, "revert HEAD~1");
    assert!(text.contains("conflict"), "{text}");
    assert!(text.contains("git add"), "{text}");
    assert!(text.contains("b10x-gates bot -- commit -F -"), "{text}");
    assert!(text.contains("git revert --abort"), "{text}");
    assert!(!text.contains("git merge --abort"), "{text}");
    assert_eq!(out(path, &["rev-parse", "HEAD"]), before);
    assert!(!out(path, &["ls-files", "-u"]).is_empty());
}

#[test]
fn merge_and_revert_refuse_a_second_revision() {
    for line in [
        "merge feature main",
        "merge",
        "merge -m message",
        "revert HEAD HEAD~1",
        "revert HEAD~2..HEAD",
        "revert HEAD~2...HEAD",
        "revert ^HEAD~1",
        "revert",
    ] {
        let text = match check(&args(line), None) {
            Ok(()) => panic!("`{line}` passed the bot argument check"),
            Err(error) => format!("{error:#}"),
        };
        assert!(text.contains("exactly one revision"), "{line}: {text}");
    }
}

#[test]
fn rebase_cherry_pick_pull_still_refused() {
    let dir = repository();
    let path = dir.path();
    let before = out(path, &["rev-parse", "HEAD"]);
    for line in [
        "rebase main",
        "cherry-pick feature",
        "pull origin main",
        "am patch.mbox",
    ] {
        let text = refusal(path, line);
        assert!(text.contains("b10x-gates bot -- merge"), "{line}: {text}");
        assert!(!text.contains("failed (exit"), "{line} reached Git: {text}");
        assert_eq!(out(path, &["rev-parse", "HEAD"]), before, "{line}");
    }
}

/// `b10x-gates bot` refuses a forbidden option and a configured merge driver before
/// it reads the bot's credential configuration.
#[test]
fn merge_refusals_come_before_credentials() {
    let dir = repository();
    let path = dir.path();
    git(path, &["config", "merge.union-lines.driver", "true"]);
    let config = path.join(".git").join("absent");
    for (line, expected) in [
        ("merge --squash feature", "`--squash`"),
        ("merge feature", "union-lines"),
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
            .args(["--repo".as_ref(), path.as_os_str()])
            .args(["bot", "--"])
            .args(args(line))
            .env_remove("B10X_GATES_POLICY")
            .env("XDG_CONFIG_HOME", &config)
            .env("B10X_BOT_CONFIG", config.join("absent-bot.json"))
            .env("B10X_BOT_KEY", config.join("absent-key.pem"))
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{line}: {stderr}");
        assert!(stderr.contains(expected), "{line}: {stderr}");
        assert!(!stderr.contains("absent-bot.json"), "{line}: {stderr}");
    }
}

/// Only the admitted options pass, by their exact names: `git revert` hands every
/// other option to its revision walker, and an unlisted `merge` option is refused
/// too. The refusal names the option and runs no Git.
#[test]
fn merge_and_revert_refuse_every_unadmitted_option() {
    let dir = repository();
    let path = dir.path();
    git(path, &["tag", "v1", "main~1"]);
    let before = out(path, &["rev-parse", "HEAD"]);
    for (line, named) in [
        ("revert --do-walk HEAD", "`--do-walk`"),
        ("revert --no-walk HEAD", "`--no-walk`"),
        ("revert --all HEAD", "`--all`"),
        ("revert --branches HEAD", "`--branches`"),
        ("revert --tags HEAD", "`--tags`"),
        ("revert --remotes HEAD", "`--remotes`"),
        ("revert --glob=refs/tags/* HEAD", "`--glob`"),
        ("revert --stdin HEAD", "`--stdin`"),
        ("revert --not HEAD", "`--not`"),
        ("revert --reflog HEAD", "`--reflog`"),
        ("revert --main 1 HEAD", "`--main`"),
        ("revert --no-signoff HEAD", "`--no-signoff`"),
        ("revert --no-edit=x HEAD", "`--no-edit=`"),
        ("revert -q HEAD", "`-q`"),
        ("revert -3 HEAD", "`-3`"),
        ("revert -i HEAD", "`-i`"),
        ("merge --autostash feature", "`--autostash`"),
        ("merge --log feature", "`--log`"),
        ("merge --no-f feature", "`--no-f`"),
        ("merge --into=x feature", "`--into`"),
        ("merge --no-commit feature", "`--no-commit`"),
        ("merge -r feature", "`-r`"),
        ("merge -qr feature", "`-r`"),
    ] {
        let text = match check(&args(line), None) {
            Ok(()) => panic!("`{line}` passed the bot argument check"),
            Err(error) => format!("{error:#}"),
        };
        assert!(text.contains(named), "{line}: {text}");
        let text = refusal(path, line);
        assert!(!text.contains("failed (exit"), "{line} reached Git: {text}");
        assert_eq!(out(path, &["rev-parse", "HEAD"]), before, "{line}");
    }
}

/// Every admitted option passes the argument check, in each form it takes.
#[test]
fn merge_and_revert_admit_each_listed_option() {
    for line in [
        "merge --no-ff --quiet --verbose --stat --no-stat --summary feature",
        "merge --compact-summary --signoff --no-signoff --no-edit feature",
        "merge --into-name main --cleanup strip --into-name=main --cleanup=strip feature",
        "merge --gpg-sign --gpg-sign=key --no-gpg-sign -S -Skey feature",
        "merge --verify-signatures --no-verify-signatures --progress --no-progress feature",
        "merge --rerere-autoupdate --no-rerere-autoupdate feature",
        "merge --overwrite-ignore --no-overwrite-ignore -qv -m message feature",
        "merge -Ffile feature",
        "revert --mainline 1 --mainline=1 -m1 --cleanup strip --cleanup=verbatim HEAD",
        "revert --no-edit --signoff --gpg-sign --gpg-sign=key --no-gpg-sign -S HEAD",
        "revert --rerere-autoupdate --no-rerere-autoupdate --reference HEAD",
    ] {
        check(&args(line), None).unwrap_or_else(|e| panic!("`{line}` refused: {e:#}"));
    }
}

/// The one revision is resolved to its commit before Git runs; one that names no
/// commit is refused with the cause.
#[test]
fn merge_and_revert_refuse_a_revision_naming_no_commit() {
    let dir = repository();
    let path = dir.path();
    let before = out(path, &["rev-parse", "HEAD"]);
    for line in [
        "merge absent",
        "revert absent",
        "merge HEAD^{tree}",
        "revert HEAD:base.txt",
    ] {
        let text = refusal(path, line);
        assert!(text.contains("does not name one commit"), "{line}: {text}");
        assert_eq!(out(path, &["rev-parse", "HEAD"]), before, "{line}");
        assert!(!exists(path, "MERGE_HEAD"), "{line}");
    }
}

/// Merging by hash keeps the message Git prepares for the name: a fetched branch is
/// named as `git merge FETCH_HEAD` names it, and only its first for-merge line is
/// merged.
#[test]
fn merge_of_fetch_head_merges_its_first_line_under_its_name() {
    let dir = repository();
    let path = dir.path();
    git(path, &["branch", "other", "main~1"]);
    git(path, &["switch", "-q", "other"]);
    commit_file(path, "other.txt", "other\n", "add other");
    git(path, &["switch", "-q", "main"]);
    let feature = out(path, &["rev-parse", "feature"]);
    let other = out(path, &["rev-parse", "other"]);
    fs::write(
        path.join(".git/FETCH_HEAD"),
        format!("{feature}\t\tbranch 'feature' of example\n{other}\t\tbranch 'other' of example\n"),
    )
    .unwrap();
    bot(path, "merge FETCH_HEAD").unwrap();
    assert_eq!(
        out(path, &["log", "-1", "--format=%P", "HEAD"])
            .split(' ')
            .count(),
        2
    );
    assert_eq!(out(path, &["rev-parse", "HEAD^2"]), feature);
    assert_eq!(
        out(path, &["log", "-1", "--format=%s"]),
        "Merge branch 'feature' of example"
    );
    assert_eq!(identity(path, "HEAD"), bot_identity());
}

/// Staged changes would ride inside the Revert commit: refused, naming the cause, and
/// the index is left as it was.
#[test]
fn revert_refuses_staged_changes() {
    let dir = repository();
    let path = dir.path();
    fs::write(path.join("staged.txt"), "staged\n").unwrap();
    git(path, &["add", "staged.txt"]);
    let before = out(path, &["rev-parse", "HEAD"]);
    let text = refusal(path, "revert HEAD");
    assert!(text.contains("index differs from HEAD"), "{text}");
    assert!(text.contains("Revert commit"), "{text}");
    assert_eq!(out(path, &["rev-parse", "HEAD"]), before);
    assert_eq!(
        out(path, &["diff", "--cached", "--name-only"]),
        "staged.txt"
    );
    assert!(!exists(path, "REVERT_HEAD"));
}

/// A refusal names the configuration file relative to the Git directory, never by
/// its local path, for each file the driver check reads.
#[test]
fn driver_refusals_name_the_file_not_its_path() {
    let dir = repository();
    let path = dir.path();
    git(path, &["config", "extensions.worktreeConfig", "true"]);
    git(path, &["config", "--worktree", "include.path", "x.config"]);
    let text = refusal(path, "revert HEAD");
    assert!(text.contains("`.git/config.worktree` includes"), "{text}");
    assert!(!text.contains(path.to_str().unwrap()), "{text}");

    let dir = repository();
    let path = dir.path();
    fs::write(path.join(".git/config"), "[core\n").unwrap();
    let text = refusal(path, "merge feature");
    assert!(!text.contains(path.to_str().unwrap()), "{text}");
}

/// `merge` and `revert` never use a credential, so the binary mints none: they run
/// with the bot's credential configuration absent.
#[test]
fn merge_and_revert_mint_no_credential() {
    let dir = repository();
    let path = dir.path();
    let config = path.join(".git").join("absent");
    for line in ["merge feature", "revert -m 1 HEAD"] {
        let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
            .args(["--repo".as_ref(), path.as_os_str()])
            .args(["bot", "--"])
            .args(args(line))
            .env_remove("B10X_GATES_POLICY")
            .env("XDG_CONFIG_HOME", &config)
            .env("B10X_BOT_CONFIG", config.join("absent-bot.json"))
            .env("B10X_BOT_KEY", config.join("absent-key.pem"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{line}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(identity(path, "HEAD"), bot_identity(), "{line}");
    }
    assert_eq!(
        out(path, &["log", "-1", "--format=%s"]),
        "Revert \"Merge branch 'feature'\""
    );
}
