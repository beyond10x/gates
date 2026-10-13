//! Adversarial cases for the merge-baseline and delete-branch defaults wave
//! (`gates.delivery.DeleteBranch` in `ess/domains/delivery.yaml`).
use b10x_gates::bot_args::delete_branch_repository;
use std::{path::Path, process::Command};

const REPOSITORY: &str = "example/sample";

fn git(root: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(root)
        .args([
            "-c",
            "user.name=example",
            "-c",
            "user.email=example@example.invalid",
            "-c",
            "init.templateDir=",
            "-c",
            "protocol.file.allow=always",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .status()
        .unwrap();
    assert!(status.success(), "git {args:?}");
}

/// Install a hooks configuration as `b10x-gates install` writes it: directory 0700,
/// file 0600, in the repository's common directory.
fn install_configuration(root: &Path, repository: &str) {
    use std::os::unix::fs::PermissionsExt;
    let directory = root.join(".git/b10x-gates-hooks");
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let config = directory.join("config.json");
    std::fs::write(
        &config,
        serde_json::to_vec(&serde_json::json!({
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
    std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// A repository whose hooks are installed and that later became shallow (`git fetch
/// --depth`, or a `--depth` clone the hooks were copied into). Its configuration is
/// present and trusted, so `delete_branch_repository` must either return its repository
/// or refuse naming the cause. It returns `None` instead ("neither exists"), because
/// `Git::new`'s history guards fail and are swallowed as "not a repository", and the
/// binary then tells the operator to run `b10x-gates install`, which refuses the same
/// shallow repository. The doc comment says `None` only "when neither exists".
#[test]
fn a_shallow_repository_with_installed_hooks_is_not_reported_as_uninstalled() {
    let source = tempfile::tempdir().unwrap();
    git(source.path(), &["init", "-q", "-b", "main"]);
    for n in ["one", "two"] {
        std::fs::write(source.path().join("file"), n).unwrap();
        git(source.path(), &["add", "file"]);
        git(source.path(), &["commit", "-q", "-m", n]);
    }
    let clone = tempfile::tempdir().unwrap();
    let url = format!("file://{}", source.path().display());
    git(
        clone.path(),
        &["clone", "-q", "--depth", "1", &url, "checkout"],
    );
    let root = clone.path().join("checkout");
    assert!(
        root.join(".git/shallow").exists(),
        "the fixture must be shallow"
    );
    install_configuration(&root, REPOSITORY);
    match delete_branch_repository(&root, None) {
        Ok(Some(repository)) => assert_eq!(repository, REPOSITORY),
        Ok(None) => panic!(
            "an installed, trusted configuration was reported as absent: the operator is told \
             to run `b10x-gates install`, which refuses a shallow repository"
        ),
        Err(error) => {
            let text = format!("{error:#}");
            assert!(
                text.contains("shallow"),
                "refused without its cause: {text}"
            );
        }
    }
}
