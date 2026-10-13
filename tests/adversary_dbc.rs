//! Adversary cases for the delete-branch comparison and install-defaults wave
//! (`story:bot-delete-branch-compare`, `story:install-from-installed-config`).
//! GitHub is a double behind `delivery::RemoteBranches` applying the real client's
//! path guard, so no credential is ever minted; install runs the binary against
//! fixture repositories and an isolated configuration home.
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    bot_args::delete_branch,
    delivery::{RemoteBranches, api_path_admitted, delete_remote_branch},
    hooks::Config,
    policy::{Policy, Repository},
};
use serde_json::{Value, json};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const TIP: &str = "1111111111111111111111111111111111111111";

// ---------------------------------------------------------------- delete-branch

/// GitHub as a table of answers per path; `None` is a 404. An unexpected path panics.
#[derive(Default)]
struct Fake {
    answers: RefCell<HashMap<String, Option<Value>>>,
    reads: RefCell<Vec<String>>,
    deletes: RefCell<Vec<String>>,
}

impl Fake {
    fn answer(self, path: &str, value: Option<Value>) -> Self {
        self.answers.borrow_mut().insert(path.to_string(), value);
        self
    }
}

impl RemoteBranches for Fake {
    fn read(&self, path: &str) -> anyhow::Result<Option<Value>> {
        anyhow::ensure!(api_path_admitted(path), "invalid GitHub API path");
        self.reads.borrow_mut().push(path.to_string());
        self.answers
            .borrow()
            .get(path)
            .cloned()
            .unwrap_or_else(|| panic!("unexpected read of {path}"))
            .map_or(Ok(None), |v| Ok(Some(v)))
    }

    fn delete(&self, path: &str) -> anyhow::Result<()> {
        anyhow::ensure!(api_path_admitted(path), "invalid GitHub API path");
        self.deletes.borrow_mut().push(path.to_string());
        Ok(())
    }
}

fn deletion(branch: &str) -> b10x_gates::bot_args::BranchDeletion {
    let args = vec!["delete-branch".to_string(), branch.to_string()];
    delete_branch(&args, Some("example/sample"))
        .unwrap_or_else(|e| panic!("`{branch}` refused: {e:#}"))
}

fn bot_authority() -> Value {
    Value::Array(
        ["creation", "update", "deletion", "non_fast_forward"]
            .into_iter()
            .map(|kind| json!({"type": kind, "ruleset_id": 1}))
            .collect(),
    )
}

/// The guard `api_path_admitted` was extracted from: an absolute path with no `..`
/// and no `#`. Pins every refusal of the inline guard it replaced, so loosening the
/// shared function (which every test double now trusts) turns this red.
#[test]
fn the_extracted_guard_refuses_everything_the_inline_guard_refused() {
    for refused in [
        "",
        "repos/example/sample",
        "/repos/example/sample/..",
        "/repos/example/../sample",
        "/repos/example/sample/compare/a...b",
        "/repos/example/sample/compare/a..b",
        "/..",
        "/repos/example/sample#fragment",
        "/repos/example/sample/branches/a?b#c",
    ] {
        let inline = refused.starts_with('/') && !refused.contains("..") && !refused.contains('#');
        assert!(!inline, "fixture error: {refused:?} is admitted inline");
        assert!(!api_path_admitted(refused), "guard admits {refused:?}");
    }
    for admitted in [
        "/",
        "/repos/example/sample",
        &format!("/repos/example/sample/compare/{TIP}%2E%2E%2Emain"),
        "/repos/example/sample/branches/wave/a%23b%25c",
        "/repos/example/sample/rules/branches/wave/one?per_page=100",
    ] {
        assert!(api_path_admitted(admitted), "guard refuses {admitted:?}");
    }
}

/// A `%` in the branch or the default branch is itself encoded (`%25`), so neither
/// name can forge a second `%2E%2E%2E` separator or a `%2F` segment break: the
/// comparison names exactly the tip and the default branch GitHub reported.
#[test]
fn percent_sequences_in_names_cannot_forge_the_comparison_separator() {
    let branch = "wave/x%2E%2E%2Emain%2Fother";
    let default = "trunk%2E%2E%2Eother%2F..";
    let encoded_branch = "wave/x%252E%252E%252Emain%252Fother";
    // `..` stays literal in a segment, so a default holding it is refused by the guard
    // before any comparison is sent; use one without it for the admitted case.
    let default_ok = "trunk%2E%2E%2Eother%2Fx";
    let encoded_default_ok = "trunk%252E%252E%252Eother%252Fx";
    let compare = format!("/repos/example/sample/compare/{TIP}%2E%2E%2E{encoded_default_ok}");
    let fake = Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": default_ok})),
        )
        .answer(
            &format!("/repos/example/sample/branches/{encoded_branch}"),
            Some(json!({"name": branch, "protection": {"enabled": false}, "commit": {"sha": TIP}})),
        )
        .answer(
            &compare,
            Some(json!({"status": "ahead", "merge_base_commit": {"sha": TIP}})),
        )
        .answer(
            &format!("/repos/example/sample/rules/branches/{encoded_branch}?per_page=100"),
            Some(bot_authority()),
        );
    delete_remote_branch(&fake, &deletion(branch)).unwrap_or_else(|e| panic!("{e:#}"));
    let reads = fake.reads.borrow();
    let compared: Vec<&String> = reads.iter().filter(|p| p.contains("/compare/")).collect();
    assert_eq!(compared, vec![&compare]);
    assert_eq!(compare.matches("%2E%2E%2E").count(), 1, "{compare}");
    assert_eq!(
        *fake.deletes.borrow(),
        vec![format!(
            "/repos/example/sample/git/refs/heads/{encoded_branch}"
        )]
    );

    // A default branch carrying a literal `..` (no valid ref does) never reaches GitHub.
    let fake = Fake::default()
        .answer(
            "/repos/example/sample",
            Some(json!({"default_branch": default})),
        )
        .answer(
            "/repos/example/sample/branches/wave/one",
            Some(json!({"name": "wave/one", "protection": {"enabled": false}, "commit": {"sha": TIP}})),
        );
    let error = delete_remote_branch(&fake, &deletion("wave/one")).expect_err("admitted");
    assert!(
        format!("{error:#}").contains("invalid GitHub API path"),
        "{error:#}"
    );
    assert!(fake.deletes.borrow().is_empty());
    assert!(
        !fake.reads.borrow().iter().any(|p| p.contains("/compare/")),
        "{:?}",
        fake.reads.borrow()
    );
}

// ---------------------------------------------------------------------- install

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

/// A repository with one commit, a private directory holding an enrolling policy, a
/// key and a scanner, and a configuration home whose default key and scanner exist
/// (but no default policy).
struct Fixture {
    repo: TempDir,
    private: TempDir,
    home: TempDir,
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
        let fixture = Self {
            repo,
            private: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
        };
        let policy = Policy {
            version: 1,
            nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
            forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
            forbidden_patterns: vec![],
            allow_patterns: vec![],
            repositories: [(
                REPOSITORY.to_string(),
                Repository {
                    id: "123".into(),
                    baseline,
                },
            )]
            .into_iter()
            .collect(),
            signers: BTreeMap::new(),
            exceptions: vec![],
        };
        let write = |path: &Path, bytes: &[u8]| {
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
            b10x_gates::policy::private_write(path, bytes).unwrap();
        };
        write(
            &fixture.private.path().join("policy.json"),
            &serde_json::to_vec(&policy).unwrap(),
        );
        write(&fixture.key(), b"0".repeat(64).as_slice());
        write(&fixture.scanner(), b"not executed");
        write(&fixture.default_key(), b"1".repeat(64).as_slice());
        write(&fixture.default_scanner(), b"not executed either");
        fixture
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
    fn gates_home(&self) -> PathBuf {
        self.home.path().join("config/b10x/gates")
    }
    fn default_key(&self) -> PathBuf {
        self.gates_home().join("signing-key")
    }
    fn default_scanner(&self) -> PathBuf {
        self.gates_home().join("bin/gitleaks")
    }

    /// `b10x-gates install` with exactly `extra` global flags and `env`; no policy, key
    /// or scanner environment otherwise.
    fn install(&self, extra: &[&str], env: &[(&str, &Path)]) -> Output {
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
        for (name, value) in env {
            command.env(name, value);
        }
        command.output().unwrap()
    }

    fn named(&self) -> Output {
        let policy = self.policy();
        let key = self.key();
        let scanner = self.scanner();
        self.install(
            &[
                "--repository",
                REPOSITORY,
                "--policy",
                policy.to_str().unwrap(),
                "--key",
                key.to_str().unwrap(),
                "--gitleaks",
                scanner.to_str().unwrap(),
            ],
            &[],
        )
    }

    fn configuration_path(&self) -> PathBuf {
        self.repo.path().join(".git/b10x-gates-hooks/config.json")
    }

    fn configuration(&self) -> Config {
        serde_json::from_slice(&fs::read(self.configuration_path()).unwrap()).unwrap()
    }

    /// A configuration file written by hand with `mode`; hooks not active.
    fn write_configuration(&self, body: &Value, mode: u32) {
        let directory = self.repo.path().join(".git/b10x-gates-hooks");
        fs::create_dir_all(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join("config.json");
        fs::write(&path, serde_json::to_vec(body).unwrap()).unwrap();
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

/// Precedence for the key and the scanner: the environment wins over the installed
/// configuration, and the installed configuration wins over a default that exists.
#[test]
fn key_and_scanner_precedence_is_environment_then_installed_then_default() {
    let f = Fixture::new();
    succeeded(&f.named());
    // No flag, no environment, defaults present: the installed key and scanner stay.
    succeeded(&f.install(&[], &[]));
    let written = f.configuration();
    assert_eq!(written.key, fs::canonicalize(f.key()).unwrap());
    assert_eq!(written.scanner, fs::canonicalize(f.scanner()).unwrap());
    // The environment names the defaults' files: it wins over the installed paths.
    let default_key = f.default_key();
    let default_scanner = f.default_scanner();
    succeeded(&f.install(
        &[],
        &[
            ("B10X_GATES_KEY", &default_key),
            ("B10X_GATES_GITLEAKS", &default_scanner),
        ],
    ));
    let written = f.configuration();
    assert_eq!(written.key, fs::canonicalize(f.default_key()).unwrap());
    assert_eq!(
        written.scanner,
        fs::canonicalize(f.default_scanner()).unwrap()
    );
    assert_eq!(written.policy, f.policy());
    assert_eq!(written.repository, REPOSITORY);
}

/// An installed configuration that is a symlink, even to an owner-only file naming a
/// trusted policy, is refused and never followed.
#[test]
fn a_symlinked_installed_configuration_is_refused() {
    let f = Fixture::new();
    let elsewhere = f.private.path().join("planted.json");
    b10x_gates::policy::private_write(
        &elsewhere,
        &serde_json::to_vec(&json!({
            "repository": REPOSITORY,
            "policy": f.policy(),
            "key": f.key(),
            "scanner": f.scanner(),
            "previous": {},
            "retired_pre_push_digest": null,
            "installed_version": "0.0.0"
        }))
        .unwrap(),
    )
    .unwrap();
    let directory = f.repo.path().join(".git/b10x-gates-hooks");
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, directory.join("config.json")).unwrap();
    let stderr = refused(&f.install(&[], &[]));
    assert!(stderr.contains("config.json"), "{stderr}");
    assert!(
        fs::symlink_metadata(f.configuration_path())
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

/// A policy the installed configuration names through a symlink is refused, as a
/// policy named by the flag is.
#[test]
fn a_symlinked_policy_named_by_the_installed_configuration_is_refused() {
    let f = Fixture::new();
    let link = f.private.path().join("linked-policy.json");
    std::os::unix::fs::symlink(f.policy(), &link).unwrap();
    f.write_configuration(
        &json!({
            "repository": REPOSITORY,
            "policy": link,
            "key": f.key(),
            "scanner": f.scanner(),
            "previous": {},
            "retired_pre_push_digest": null,
            "installed_version": "0.0.0"
        }),
        0o600,
    );
    let stderr = refused(&f.install(&[], &[]));
    assert!(stderr.contains("linked-policy.json"), "{stderr}");
    assert!(
        stderr.contains("named by the installed hook configuration"),
        "{stderr}"
    );
}

/// A linked worktree reinstalls from the common directory's configuration: the same
/// repository and policy, the hooks still in the one common directory.
#[test]
fn a_linked_worktree_reinstalls_from_the_common_configuration() {
    let f = Fixture::new();
    succeeded(&f.named());
    let linked = f.private.path().join("linked");
    git(
        f.repo.path(),
        &[
            "worktree",
            "add",
            "-q",
            "--detach",
            linked.to_str().unwrap(),
        ],
    );
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .arg("--repo")
        .arg(&linked)
        .arg("install")
        .env("HOME", f.home.path())
        .env("XDG_CONFIG_HOME", f.home.path().join("config"))
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("B10X_GATES_POLICY")
        .env_remove("B10X_GATES_KEY")
        .env_remove("B10X_GATES_GITLEAKS")
        .output()
        .unwrap();
    succeeded(&output);
    let written = f.configuration();
    assert_eq!(written.repository, REPOSITORY);
    assert_eq!(written.policy, f.policy());
    assert!(!linked.join(".git/b10x-gates-hooks").exists());
}

/// An installed configuration as an earlier install wrote it, with `mode`; hooks not
/// active (`core.hooksPath` unset), as after another hook manager took the path over or
/// the repository was moved.
fn left_behind(f: &Fixture, mode: u32) {
    f.write_configuration(
        &json!({
            "repository": REPOSITORY,
            "policy": f.policy(),
            "key": f.key(),
            "scanner": f.scanner(),
            "previous": {},
            "retired_pre_push_digest": null,
            "installed_version": "0.0.0"
        }),
        mode,
    );
}

fn install_naming_repository_and_policy(f: &Fixture) -> Output {
    let policy = f.policy();
    f.install(
        &[
            "--repository",
            REPOSITORY,
            "--policy",
            policy.to_str().unwrap(),
        ],
        &[],
    )
}

/// DEFECT. An unparsable installed configuration is refused with the remedy "pass
/// --repository <owner>/<repo> and --policy <path>", and following it is refused again
/// with the same remedy: the configuration is read whenever any one of the four values
/// (repository, policy, key, scanner) is unnamed. Before the change this install
/// succeeded (the key and scanner defaults exist; with the hooks inactive
/// `hooks::install` never reads the old configuration) and replaced the file.
#[test]
fn following_the_refusals_remedy_installs_past_an_unparsable_configuration() {
    let f = Fixture::new();
    left_behind(&f, 0o600);
    b10x_gates::policy::private_write(&f.configuration_path(), b"{\"repository\": 1}").unwrap();
    let stderr = refused(&f.install(&[], &[]));
    assert!(
        stderr.contains("pass --repository <owner>/<repo> and --policy <path>"),
        "{stderr}"
    );
    succeeded(&install_naming_repository_and_policy(&f));
    let written = f.configuration();
    assert_eq!(written.repository, REPOSITORY);
    assert_eq!(written.policy, f.policy());
}

/// DEFECT. Naming the repository and the policy explicitly no longer installs over a
/// left-behind configuration that is not owner-only; before the change it did, and
/// the rewrite made the configuration owner-only again. The refusal names no remedy.
#[test]
fn an_explicit_repository_and_policy_install_past_a_configuration_that_is_not_owner_only() {
    let f = Fixture::new();
    left_behind(&f, 0o644);
    succeeded(&install_naming_repository_and_policy(&f));
    let mode = fs::metadata(f.configuration_path())
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o077, 0, "{mode:o}");
}
