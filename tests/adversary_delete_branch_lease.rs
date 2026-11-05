//! Adversary pass 1 on `story:bot-delete-branch-atomic`: the compare-and-delete
//! `compare_and_delete_branch` runs against local bare repositories. A push that lands
//! after the remote's advertisement (inside the remote, from its `pre-receive` hook) is
//! the window the client-side lease cannot see; the remote's own old-object compare
//! must keep it. The caller's environment reaches the scratch push through the child
//! process entry points, so no test here changes this process's environment.
use b10x_gates::delivery::{CompareAndDelete, bot_git, compare_and_delete_branch};
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("u4adv-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// A bare repository standing in for the remote.
struct Remote {
    dir: tempfile::TempDir,
}

impl Remote {
    /// `main` and `wave/one` at one commit, which is returned.
    fn new() -> (Self, String) {
        let remote = Remote { dir: scratch() };
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

    fn commit(&self, parent: Option<&str>) -> String {
        let tree = self.git(&["mktree"]);
        let mut args = vec!["commit-tree", tree.as_str(), "-m", "change"];
        args.extend(parent.map(|parent| ["-p", parent]).into_iter().flatten());
        self.git(&args)
    }

    /// Where the full ref `reference` points; `None` when it does not exist.
    fn at(&self, reference: &str) -> Option<String> {
        let output = self.command(&["rev-parse", "--verify", "--quiet", reference]);
        output
            .status
            .success()
            .then(|| String::from_utf8(output.stdout).unwrap().trim().to_string())
    }

    /// Install an executable hook in the remote.
    fn hook(&self, name: &str, body: &str) {
        let path = self.dir.path().join("hooks").join(name);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    }

    fn url(&self) -> &str {
        self.dir.path().to_str().unwrap()
    }
}

/// A push that lands inside the remote after it advertised `wave/one` at `tip` (the
/// client-side lease passes) and before the deletion is applied is kept: only the
/// remote's compare of the old object can refuse here, and the refusal names the tip.
#[test]
fn the_remote_keeps_a_push_that_lands_after_its_advertisement() {
    let (remote, tip) = Remote::new();
    let next = remote.commit(Some(&tip));
    remote.hook(
        "pre-receive",
        &format!(
            "unset GIT_QUARANTINE_PATH GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES\n\
             git update-ref refs/heads/wave/one {next}"
        ),
    );
    let result = compare_and_delete_branch(remote.url(), "wave/one", &tip, None);
    assert_eq!(
        remote.at("refs/heads/wave/one").as_deref(),
        Some(next.as_str()),
        "a push after the advertisement was deleted with the branch: {result:?}"
    );
    assert_eq!(
        result.unwrap_or_else(|e| panic!("{e:#}")),
        CompareAndDelete::Moved(Some(next))
    );
}

/// The branch deleted and created again at another tip after the advertisement is
/// kept at the new tip.
#[test]
fn the_remote_keeps_a_branch_recreated_after_its_advertisement() {
    let (remote, tip) = Remote::new();
    // Two generations on, so its id differs from `tip` (a root commit made in the same
    // second would be `tip` itself).
    let other = remote.commit(Some(&remote.commit(Some(&tip))));
    remote.hook(
        "pre-receive",
        &format!(
            "unset GIT_QUARANTINE_PATH GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES\n\
             git update-ref -d refs/heads/wave/one\n\
             git update-ref refs/heads/wave/one {other}"
        ),
    );
    let result = compare_and_delete_branch(remote.url(), "wave/one", &tip, None);
    assert_eq!(
        remote.at("refs/heads/wave/one").as_deref(),
        Some(other.as_str()),
        "{result:?}"
    );
    assert_eq!(
        result.unwrap_or_else(|e| panic!("{e:#}")),
        CompareAndDelete::Moved(Some(other))
    );
}

/// Names that look like options or refspec syntax delete only themselves.
#[test]
fn option_and_refspec_shaped_names_delete_only_themselves() {
    let names = [
        "-x",
        "--force",
        "--all",
        "-d",
        "+x",
        "x+y",
        "wave/-one",
        "@x",
    ];
    for name in names {
        let (remote, tip) = Remote::new();
        let others: Vec<String> = names
            .iter()
            .filter(|other| **other != name)
            .map(|other| format!("refs/heads/{other}"))
            .chain(["refs/heads/main".into(), format!("refs/tags/{name}")])
            .collect();
        for reference in others.iter().chain([&format!("refs/heads/{name}")]) {
            remote.git(&["update-ref", reference, &tip]);
        }
        let result = compare_and_delete_branch(remote.url(), name, &tip, None);
        assert_eq!(
            result.unwrap_or_else(|e| panic!("{name}: {e:#}")),
            CompareAndDelete::Deleted,
            "{name}"
        );
        assert_eq!(remote.at(&format!("refs/heads/{name}")), None, "{name}");
        for reference in &others {
            assert_eq!(
                remote.at(reference).as_deref(),
                Some(tip.as_str()),
                "{name} took {reference} with it"
            );
        }
    }
}

/// A deletion the remote applied and whose report was lost (the remote's process ends
/// after the ref transaction committed, as a dropped connection would) is not reported
/// as `Moved(None)`, which `delete_remote_branch` prints as "the bot deleted nothing".
#[test]
fn a_deletion_whose_report_was_lost_is_not_told_as_nothing_deleted() {
    let (remote, tip) = Remote::new();
    remote.hook(
        "reference-transaction",
        "[ \"$1\" = committed ] && kill -9 $PPID\nexit 0",
    );
    let result = compare_and_delete_branch(remote.url(), "wave/one", &tip, None);
    assert_eq!(
        remote.at("refs/heads/wave/one"),
        None,
        "fixture: the remote did not apply the deletion: {result:?}"
    );
    assert!(
        !matches!(result, Ok(CompareAndDelete::Moved(None))),
        "the remote deleted refs/heads/wave/one, and the outcome says it was gone \
         before: {result:?}"
    );
}

/// `bot_git`'s refusal of `delete-branch` describes the route as it now is: the
/// deletion is a Git push carrying the checked tip.
#[test]
fn bot_git_refusal_does_not_say_never_through_git() {
    let dir = scratch();
    let text = format!(
        "{:#}",
        bot_git(
            dir.path(),
            &["delete-branch".to_string(), "wave/one".to_string()],
            None
        )
        .expect_err("bot_git ran delete-branch")
    );
    assert!(
        !text.contains("never through Git"),
        "stale refusal text: {text}"
    );
}

/// Run `child` of this test binary with `env`; its printed outcome line.
fn run_child(child: &str, env: &[(&str, &str)]) -> String {
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
        .filter_map(|line| line.find("U4ADV ").map(|at| &line[at..]))
        .collect::<Vec<_>>()
        .join("\n")
}

fn template(dir: &Path, marker: &Path, config: &str) {
    fs::create_dir_all(dir.join("hooks")).unwrap();
    let hook = dir.join("hooks/pre-push");
    fs::write(
        &hook,
        format!(
            "#!/bin/sh\necho \"$B10X_BOT_TOKEN\" > '{}'\nexit 0\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&hook, fs::Permissions::from_mode(0o755)).unwrap();
    if !config.is_empty() {
        fs::write(dir.join("config"), config).unwrap();
    }
}

#[test]
#[ignore = "child process entry point: run by the_callers_template_directory_reaches_no_scratch_push"]
fn child_delete_with_callers_environment() {
    let remote = std::env::var("U4ADV_REMOTE").unwrap();
    let tip = std::env::var("U4ADV_TIP").unwrap();
    let result = compare_and_delete_branch(&remote, "wave/one", &tip, None);
    println!("U4ADV {result:?}");
}

/// `GIT_TEMPLATE_DIR` in the caller's environment wins over `-c init.templateDir=`:
/// its hooks and configuration would be copied into the scratch repository, so a
/// `pre-push` hook runs with the bot's environment and a `pushInsteadOf` sends the
/// deletion to another remote.
#[test]
fn the_callers_template_directory_reaches_no_scratch_push() {
    let (remote, tip) = Remote::new();
    let (decoy, decoy_tip) = Remote::new();
    let work = scratch();
    let marker = work.path().join("pre-push-ran");
    let templates = work.path().join("templates");
    template(
        &templates,
        &marker,
        &format!(
            "[core]\n\trepositoryformatversion = 0\n\tbare = true\n\
             [url \"{}\"]\n\tpushInsteadOf = {}\n",
            decoy.url(),
            remote.url()
        ),
    );
    let outcome = run_child(
        "child_delete_with_callers_environment",
        &[
            ("GIT_TEMPLATE_DIR", templates.to_str().unwrap()),
            ("U4ADV_REMOTE", remote.url()),
            ("U4ADV_TIP", &tip),
        ],
    );
    let hook_ran = marker.exists();
    let decoy_now = decoy.at("refs/heads/wave/one");
    let remote_now = remote.at("refs/heads/wave/one");
    assert!(
        !hook_ran && decoy_now.as_deref() == Some(decoy_tip.as_str()) && remote_now.is_none(),
        "caller's GIT_TEMPLATE_DIR reached the scratch push: pre-push ran {hook_ran}, \
         decoy wave/one {decoy_now:?} (was {decoy_tip}), remote wave/one {remote_now:?}; \
         child: {outcome}"
    );
}

#[test]
#[ignore = "child process entry point: run by every_outcome_removes_the_scratch_repository"]
fn child_every_outcome() {
    let remote = std::env::var("U4ADV_REMOTE").unwrap();
    let tip = std::env::var("U4ADV_TIP").unwrap();
    let missing = format!("{remote}-missing");
    for (case, remote, branch) in [
        ("refused", remote.as_str(), "keep"),
        ("moved", remote.as_str(), "moved"),
        ("gone", remote.as_str(), "gone"),
        ("unreachable", missing.as_str(), "wave/one"),
        ("deleted", remote.as_str(), "wave/one"),
    ] {
        let result = compare_and_delete_branch(remote, branch, &tip, None);
        println!("U4ADV {case} {:?}", result.map_err(|e| format!("{e:#}")));
    }
}

/// Deleted, moved, gone, refused at the checked tip and an unreachable remote all leave
/// the temporary directory as they found it.
#[test]
fn every_outcome_removes_the_scratch_repository() {
    let (remote, tip) = Remote::new();
    let next = remote.commit(Some(&tip));
    remote.git(&["update-ref", "refs/heads/moved", &next]);
    // `keep` is refused by a remote hook while it is at the checked tip.
    remote.git(&["update-ref", "refs/heads/keep", &tip]);
    remote.hook(
        "pre-receive",
        "while read old new ref; do [ \"$ref\" = refs/heads/keep ] && exit 1; done\nexit 0",
    );
    let temporary = scratch();
    let outcome = run_child(
        "child_every_outcome",
        &[
            ("TMPDIR", temporary.path().to_str().unwrap()),
            ("U4ADV_REMOTE", remote.url()),
            ("U4ADV_TIP", &tip),
        ],
    );
    let left: Vec<_> = fs::read_dir(temporary.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert!(left.is_empty(), "left behind {left:?} after:\n{outcome}");
    for expected in [
        "U4ADV refused Err(".to_string(),
        format!("U4ADV moved Ok(Moved(Some(\"{next}\")))"),
        "U4ADV gone Ok(Moved(None))".to_string(),
        "U4ADV unreachable Err(".to_string(),
        "U4ADV deleted Ok(Deleted)".to_string(),
    ] {
        assert!(outcome.contains(&expected), "{expected} not in:\n{outcome}");
    }
    assert!(outcome.contains("while it is at"), "{outcome}");
    assert_eq!(remote.at("refs/heads/keep").as_deref(), Some(tip.as_str()));
    assert_eq!(
        remote.at("refs/heads/moved").as_deref(),
        Some(next.as_str())
    );
}
