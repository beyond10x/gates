//! `b10x-gates install` without `--repository` or `--policy` reuses what the installed
//! hooks' protected configuration names (`story:install-from-installed-config`,
//! modelled as `gates.delivery.InstallHooks` in `ess/domains/delivery.yaml`). Each test
//! is named after the outcome it holds the binary to. The configuration home is an
//! empty directory, so no default policy is ever found by accident.
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    hooks::Config,
    policy::{Policy, Repository},
};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const REPOSITORY: &str = "example/repository";

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", BOT_NAME)
        .env("GIT_AUTHOR_EMAIL", BOT_EMAIL)
        .env("GIT_COMMITTER_NAME", BOT_NAME)
        .env("GIT_COMMITTER_EMAIL", BOT_EMAIL)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Git fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

/// A repository with one commit, a private directory holding a policy that enrols
/// `REPOSITORY`, a key and a scanner path, and an empty configuration home.
struct Fixture {
    repo: TempDir,
    private: TempDir,
    home: TempDir,
    baseline: String,
}

impl Fixture {
    fn new() -> Self {
        let repo = tempfile::tempdir().unwrap();
        git(
            repo.path(),
            &[
                "-c",
                "init.templateDir=",
                "init",
                "-q",
                "--initial-branch=main",
            ],
        );
        fs::write(repo.path().join("readme"), "initial safe bytes\n").unwrap();
        git(repo.path(), &["add", "."]);
        git(repo.path(), &["commit", "-qm", "initial"]);
        let baseline = git(repo.path(), &["rev-parse", "HEAD"]);
        let private = tempfile::tempdir().unwrap();
        let fixture = Self {
            repo,
            private,
            home: tempfile::tempdir().unwrap(),
            baseline,
        };
        fixture.write_policy("policy.json", &[REPOSITORY]);
        b10x_gates::policy::private_write(&fixture.key(), b"0".repeat(64).as_slice()).unwrap();
        b10x_gates::policy::private_write(&fixture.scanner(), b"not executed").unwrap();
        fixture
    }

    /// A policy at `name` in the private directory enrolling `repositories`.
    fn write_policy(&self, name: &str, repositories: &[&str]) -> PathBuf {
        let policy = Policy {
            version: 1,
            nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
            forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
            forbidden_patterns: vec![],
            allow_patterns: vec![],
            repositories: repositories
                .iter()
                .map(|r| {
                    (
                        r.to_string(),
                        Repository {
                            id: "123".into(),
                            baseline: self.baseline.clone(),
                        },
                    )
                })
                .collect(),
            signers: BTreeMap::new(),
            exceptions: vec![],
        };
        let path = self.private.path().join(name);
        b10x_gates::policy::private_write(&path, &serde_json::to_vec(&policy).unwrap()).unwrap();
        fs::canonicalize(path).unwrap()
    }

    fn policy(&self) -> PathBuf {
        fs::canonicalize(self.private.path().join("policy.json")).unwrap()
    }

    fn key(&self) -> PathBuf {
        self.private.path().join("key")
    }

    fn scanner(&self) -> PathBuf {
        self.private.path().join("gitleaks")
    }

    /// `b10x-gates install` with `extra` global flags, the key and scanner always
    /// named, no policy environment and an empty configuration home.
    fn install(&self, extra: &[&str], policy_env: Option<&Path>) -> Output {
        let key = self.key();
        let scanner = self.scanner();
        let mut named = vec!["--key", key.to_str().unwrap()];
        named.extend(["--gitleaks", scanner.to_str().unwrap()]);
        named.extend(extra);
        self.install_bare(&named, policy_env)
    }

    /// `b10x-gates install` with only `extra` global flags: no policy, key or scanner
    /// environment and an empty configuration home, so no default exists.
    fn install_bare(&self, extra: &[&str], policy_env: Option<&Path>) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_b10x-gates"));
        command
            .arg("--repo")
            .arg(self.repo.path())
            .args(extra)
            .arg("install")
            .env("HOME", self.home.path())
            .env("XDG_CONFIG_HOME", self.home.path().join("config"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("B10X_GATES_POLICY")
            .env_remove("B10X_GATES_KEY")
            .env_remove("B10X_GATES_GITLEAKS");
        if let Some(policy) = policy_env {
            command.env("B10X_GATES_POLICY", policy);
        }
        command.output().unwrap()
    }

    fn configuration_path(&self) -> PathBuf {
        self.repo.path().join(".git/b10x-gates-hooks/config.json")
    }

    fn configuration(&self) -> Config {
        serde_json::from_slice(&fs::read(self.configuration_path()).unwrap()).unwrap()
    }

    /// A configuration as `install` writes it, but by hand and with file `mode`, so
    /// the hooks are not active (`core.hooksPath` unset). Its key and scanner do not
    /// exist, so an install that took them over the flags would fail.
    fn write_configuration(&self, repository: &str, policy: &Path, mode: u32) {
        let directory = self.repo.path().join(".git/b10x-gates-hooks");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("config.json");
        fs::write(
            &path,
            serde_json::to_vec(&json!({
                "repository": repository,
                "policy": policy,
                "key": self.private.path().join("configured-key"),
                "scanner": self.private.path().join("configured-gitleaks"),
                "previous": {},
                "retired_pre_push_digest": null,
                "installed_version": "0.0.0"
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    }
}

fn succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn refused(output: &Output) -> String {
    assert!(!output.status.success(), "install was admitted");
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `installed`: a reinstall with no flag and no environment names the same
/// repository, policy, key and scanner as the installation before it.
#[test]
fn reinstalls_from_the_installed_configuration_without_flags() {
    let f = Fixture::new();
    let policy = f.policy();
    succeeded(&f.install(
        &[
            "--repository",
            REPOSITORY,
            "--policy",
            policy.to_str().unwrap(),
        ],
        None,
    ));
    let first = f.configuration();
    succeeded(&f.install_bare(&[], None));
    let second = f.configuration();
    assert_eq!(second.key, fs::canonicalize(f.key()).unwrap());
    assert_eq!(second.key, first.key);
    assert_eq!(second.scanner, fs::canonicalize(f.scanner()).unwrap());
    assert_eq!(second.scanner, first.scanner);
    assert_eq!(second.repository, REPOSITORY);
    assert_eq!(second.repository, first.repository);
    assert_eq!(second.policy, policy);
    assert_eq!(second.policy, first.policy);
}

/// A flag or `B10X_GATES_POLICY` wins over the installed configuration, whose policy,
/// key and scanner paths here do not exist and whose repository is another one.
#[test]
fn an_explicit_repository_and_policy_win_over_the_installed_configuration() {
    let f = Fixture::new();
    let other = f.write_policy("other.json", &[REPOSITORY, "example/other"]);
    let absent = f.private.path().join("absent.json");
    f.write_configuration("example/other", &absent, 0o600);
    succeeded(&f.install(
        &[
            "--repository",
            REPOSITORY,
            "--policy",
            other.to_str().unwrap(),
        ],
        None,
    ));
    let written = f.configuration();
    assert_eq!(written.repository, REPOSITORY);
    assert_eq!(written.policy, other);
    assert_eq!(written.key, fs::canonicalize(f.key()).unwrap());
    assert_eq!(written.scanner, fs::canonicalize(f.scanner()).unwrap());
    // The environment wins as the flag does; the repository still comes from the
    // configuration when no flag names it.
    let f = Fixture::new();
    let other = f.write_policy("other.json", &["example/other"]);
    f.write_configuration("example/other", &absent, 0o600);
    succeeded(&f.install(&[], Some(&other)));
    let written = f.configuration();
    assert_eq!(written.repository, "example/other");
    assert_eq!(written.policy, other);
}

/// `untrusted-configuration`: a configuration others can read is refused with its
/// cause, never skipped as absent.
#[test]
fn refuses_a_configuration_that_is_not_owner_only() {
    let f = Fixture::new();
    f.write_configuration(REPOSITORY, &f.policy(), 0o644);
    let stderr = refused(&f.install(&[], None));
    assert!(stderr.contains("config.json"), "{stderr}");
    assert!(stderr.contains("0644"), "{stderr}");
}

/// `untrusted-configuration`: a configured repository that is not `<owner>/<repo>`
/// is refused, naming it and the file; so is a configuration that does not parse.
#[test]
fn refuses_a_configuration_naming_a_repository_that_is_not_owner_repo() {
    let f = Fixture::new();
    f.write_configuration("example/../x", &f.policy(), 0o600);
    let stderr = refused(&f.install(&[], None));
    assert!(stderr.contains("example/../x"), "{stderr}");
    assert!(stderr.contains("config.json"), "{stderr}");
    b10x_gates::policy::private_write(&f.configuration_path(), b"{\"repository\": 1}").unwrap();
    let stderr = refused(&f.install(&[], None));
    assert!(stderr.contains("invalid"), "{stderr}");
    assert!(stderr.contains("config.json"), "{stderr}");
}

/// `no-repository` and `no-policy`: with no flag, no environment and no installed
/// configuration, each refusal names both routes.
#[test]
fn refuses_naming_both_routes_when_neither_exists() {
    let f = Fixture::new();
    let policy = f.policy();
    let stderr = refused(&f.install(&["--policy", policy.to_str().unwrap()], None));
    assert!(stderr.contains("--repository <owner>/<repo>"), "{stderr}");
    assert!(stderr.contains("installed hook configuration"), "{stderr}");
    let stderr = refused(&f.install(&["--repository", REPOSITORY], None));
    assert!(stderr.contains("--policy"), "{stderr}");
    assert!(stderr.contains("B10X_GATES_POLICY"), "{stderr}");
    assert!(stderr.contains("installed hook configuration"), "{stderr}");
    assert!(!f.configuration_path().exists());
}

/// `not-enrolled`: the policy the configuration names must still enrol the
/// repository it names.
#[test]
fn the_loaded_policy_must_still_enrol_the_configured_repository() {
    let f = Fixture::new();
    f.write_configuration("example/unenrolled", &f.policy(), 0o600);
    let stderr = refused(&f.install(&[], None));
    assert!(stderr.contains("not enrolled"), "{stderr}");
}

/// `untrusted-configuration`: the refusal of a configuration that is not owner-only
/// names the remedy that installs past it, as every other untrusted refusal does.
#[test]
fn the_not_owner_only_refusal_names_the_remedy() {
    let f = Fixture::new();
    f.write_configuration(REPOSITORY, &f.policy(), 0o644);
    let stderr = refused(&f.install(&[], None));
    assert!(stderr.contains("0644"), "{stderr}");
    assert!(
        stderr.contains("pass --repository <owner>/<repo> and --policy <path>"),
        "{stderr}"
    );
}

/// `configuration-names-another-repository`: with the policy not named, the
/// configuration is read; when `--repository` names another repository than it does,
/// install is refused naming both repositories and the remedy, and the configuration
/// is left as it was.
#[test]
fn refuses_a_configuration_naming_another_repository_than_the_flag() {
    let f = Fixture::new();
    let shared = f.write_policy("shared.json", &[REPOSITORY, "example/other"]);
    f.write_configuration("example/other", &shared, 0o600);
    let before = fs::read(f.configuration_path()).unwrap();
    let stderr = refused(&f.install(&["--repository", REPOSITORY], None));
    assert!(stderr.contains(REPOSITORY), "{stderr}");
    assert!(stderr.contains("example/other"), "{stderr}");
    assert!(stderr.contains("--policy <path>"), "{stderr}");
    assert!(stderr.contains("reinstall"), "{stderr}");
    assert_eq!(fs::read(f.configuration_path()).unwrap(), before);
}

/// A reinstall must not record the installed hooks as the hooks it preserves.
#[test]
fn a_reinstall_never_records_its_own_hooks_as_previous() {
    let f = Fixture::new();
    let policy = f.policy();
    let flags = [
        "--repository",
        REPOSITORY,
        "--policy",
        policy.to_str().unwrap(),
    ];
    succeeded(&f.install(&flags, None));
    assert!(f.configuration().previous.is_empty());
    succeeded(&f.install(&flags, None));
    assert!(f.configuration().previous.is_empty());
    succeeded(&f.install_bare(&[], None));
    assert!(f.configuration().previous.is_empty());
}

fn hooks_directory(f: &Fixture) -> PathBuf {
    fs::canonicalize(f.repo.path())
        .unwrap()
        .join(".git/b10x-gates-hooks")
}

fn with_previous(f: &Fixture, hook: &str, paths: &[&Path]) {
    let path = f.configuration_path();
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    value["previous"] = json!({ hook: paths });
    b10x_gates::policy::private_write(&path, &serde_json::to_vec(&value).unwrap()).unwrap();
}

fn flags(f: &Fixture) -> Vec<String> {
    vec![
        "--repository".into(),
        REPOSITORY.into(),
        "--policy".into(),
        f.policy().to_str().unwrap().into(),
    ]
}

fn install_with(f: &Fixture) -> Output {
    let flags = flags(f);
    let flags: Vec<&str> = flags.iter().map(String::as_str).collect();
    f.install(&flags, None)
}

/// Run an installed hook under `timeout`, which signals the whole process group, so a hook that
/// calls itself is stopped after 8 s instead of filling the machine.
fn run_hook(f: &Fixture, hook: &str) -> Output {
    Command::new("sh")
        .arg("-c")
        .arg("exec timeout -k 1 8 \"$0\" 2>&1")
        .arg(hooks_directory(f).join(hook))
        .current_dir(f.repo.path())
        .env("HOME", f.home.path())
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .unwrap()
}

/// `core.hooksPath` that names the installed directory in another spelling (here a symlink
/// to the repository) is the same directory. Install must not take its hooks for hooks it
/// preserves: each would call the hook that calls it.
#[test]
fn a_hooks_path_spelled_another_way_is_still_the_installed_directory() {
    let f = Fixture::new();
    succeed_install(&f);
    let link = f.home.path().join("repo-link");
    std::os::unix::fs::symlink(f.repo.path(), &link).unwrap();
    git(
        f.repo.path(),
        &[
            "config",
            "--local",
            "core.hooksPath",
            link.join(".git/b10x-gates-hooks").to_str().unwrap(),
        ],
    );
    succeed_install(&f);
    assert!(
        f.configuration().previous.is_empty(),
        "{:?}",
        f.configuration().previous
    );
}

/// A preserved hook that lies inside the hook directory is the installed hook itself,
/// whatever links reach it. Install does not record it.
#[test]
fn a_hook_that_resolves_into_the_installed_directory_is_not_preserved() {
    let f = Fixture::new();
    succeed_install(&f);
    let target = hooks_directory(&f).join("pre-commit");
    let old = f.repo.path().join("old-hooks");
    fs::create_dir_all(&old).unwrap();
    std::os::unix::fs::symlink(&target, old.join("pre-commit")).unwrap();
    git(
        f.repo.path(),
        &["config", "--local", "core.hooksPath", old.to_str().unwrap()],
    );
    succeed_install(&f);
    assert!(
        f.configuration().previous.is_empty(),
        "{:?}",
        f.configuration().previous
    );
}

/// A configuration that already holds such entries is repaired by the next install.
#[test]
fn install_removes_installed_hooks_from_an_existing_previous_map() {
    let f = Fixture::new();
    succeed_install(&f);
    let own = hooks_directory(&f).join("pre-commit");
    let other = f.private.path().join("kept-hook");
    with_previous(&f, "pre-commit", &[own.as_path(), other.as_path()]);
    succeed_install(&f);
    let previous = f.configuration().previous;
    assert_eq!(previous.get("pre-commit"), Some(&vec![other]));
}

/// A hook that finds itself in `previous` skips it and says so; it does not start itself.
#[test]
fn a_hook_skips_a_preserved_entry_that_is_the_hook_itself() {
    let f = Fixture::new();
    succeed_install(&f);
    let own = hooks_directory(&f).join("pre-commit");
    with_previous(&f, "pre-commit", &[own.as_path()]);
    let output = run_hook(&f, "pre-commit");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("is the hook itself"), "{text}");
    assert!(!text.contains("could not start"), "{text}");
}

/// A chain through other paths that returns to the hook stops at a depth limit.
#[test]
fn a_chain_of_preserved_hooks_stops_at_a_depth_limit() {
    let f = Fixture::new();
    succeed_install(&f);
    let own = hooks_directory(&f).join("pre-commit");
    let relay = f.private.path().join("relay");
    fs::write(
        &relay,
        format!("#!/bin/sh\nexec {} \"$@\"\n", own.display()),
    )
    .unwrap();
    fs::set_permissions(&relay, fs::Permissions::from_mode(0o755)).unwrap();
    with_previous(&f, "pre-commit", &[relay.as_path()]);
    let output = run_hook(&f, "pre-commit");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("hook chain deeper than"), "{text}");
    assert!(!text.contains("could not start"), "{text}");
}

fn succeed_install(f: &Fixture) {
    succeeded(&install_with(f));
}
