//! Security conformance for the delete-branch comparison path
//! (`story:bot-delete-branch-compare`) and the reinstall from the installed hook
//! configuration (`story:install-from-installed-config`), both modelled in
//! `ess/domains/delivery.yaml` as `gates.delivery.DeleteBranch` and
//! `gates.delivery.InstallHooks`. GitHub is a double implementing
//! `delivery::RemoteBranches` that applies the real client's path guard, so no
//! credential is minted; `install` runs the built binary against temporary fixtures
//! with an empty configuration home.
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
    collections::{BTreeMap, HashMap, VecDeque},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const REPOSITORY: &str = "example/sample";
const TIP: &str = "1111111111111111111111111111111111111111";
const MOVED: &str = "2222222222222222222222222222222222222222";

// ---------------------------------------------------------------------------
// delete-branch
// ---------------------------------------------------------------------------

/// One GitHub answer: a value, a 404 (`Ok(None)`) or a failed request (`Err`).
#[derive(Clone)]
enum Answer {
    Found(Value),
    Missing,
    Failed,
}

/// GitHub as answers per path, taken in order with the last repeated. A path with no
/// answer fails the request, as an unreachable resource would. Both verbs apply the
/// guard `Github::api_response` applies before recording anything as sent.
#[derive(Default)]
struct Fake {
    answers: RefCell<HashMap<String, VecDeque<Answer>>>,
    reads: RefCell<Vec<String>>,
    deletes: RefCell<Vec<String>>,
}

impl Fake {
    fn answer(self, path: &str, answer: Answer) -> Self {
        self.answers
            .borrow_mut()
            .entry(path.to_string())
            .or_default()
            .push_back(answer);
        self
    }
}

impl RemoteBranches for Fake {
    fn read(&self, path: &str) -> anyhow::Result<Option<Value>> {
        anyhow::ensure!(api_path_admitted(path), "invalid GitHub API path");
        self.reads.borrow_mut().push(path.to_string());
        let mut answers = self.answers.borrow_mut();
        let queue = answers
            .get_mut(path)
            .ok_or_else(|| anyhow::anyhow!("no answer for {path}"))?;
        let answer = if queue.len() > 1 {
            queue.pop_front().unwrap()
        } else {
            queue.front().cloned().unwrap()
        };
        match answer {
            Answer::Found(value) => Ok(Some(value)),
            Answer::Missing => Ok(None),
            Answer::Failed => anyhow::bail!("GitHub answered 502"),
        }
    }

    fn delete(&self, path: &str) -> anyhow::Result<()> {
        anyhow::ensure!(api_path_admitted(path), "invalid GitHub API path");
        self.deletes.borrow_mut().push(path.to_string());
        Ok(())
    }
}

fn branch_answer(name: &str, tip: &str, protected: bool) -> Answer {
    Answer::Found(json!({
        "name": name,
        "protected": true,
        "protection": {"enabled": protected},
        "commit": {"sha": tip}
    }))
}

fn bot_authority() -> Answer {
    Answer::Found(Value::Array(
        ["creation", "update", "deletion", "non_fast_forward"]
            .into_iter()
            .map(|kind| json!({"type": kind, "ruleset_id": 1}))
            .collect(),
    ))
}

fn compare_path(default: &str) -> String {
    format!("/repos/example/sample/compare/{TIP}%2E%2E%2E{default}")
}

/// The repository with default branch `default`, the branch `wave/one` at `TIP`
/// unprotected, the comparison `comparison` and the bot-authority rules.
fn remote(default: &str, comparison: Answer) -> Fake {
    Fake::default()
        .answer(
            "/repos/example/sample",
            Answer::Found(json!({"default_branch": default})),
        )
        .answer(
            "/repos/example/sample/branches/wave/one",
            branch_answer("wave/one", TIP, false),
        )
        .answer(&compare_path(default), comparison)
        .answer(
            "/repos/example/sample/rules/branches/wave/one?per_page=100",
            bot_authority(),
        )
}

fn merged(status: &str) -> Answer {
    Answer::Found(json!({"status": status, "merge_base_commit": {"sha": TIP}}))
}

fn deletion(name: &str) -> b10x_gates::bot_args::BranchDeletion {
    let args: Vec<String> = ["delete-branch", name].map(String::from).to_vec();
    delete_branch(&args, Some(REPOSITORY)).unwrap_or_else(|e| panic!("`{name}`: {e:#}"))
}

/// `gates.delivery.DeleteBranch`: every refusal outcome, the new
/// `comparison-unreadable` both as a 404 and as a failed request, ends without a
/// DELETE being sent. A default branch GitHub names with `..` makes the comparison
/// path one the guard refuses, which is an unreadable comparison and deletes nothing.
#[test]
fn every_delete_branch_refusal_sends_no_delete() {
    let protected = Fake::default()
        .answer(
            "/repos/example/sample",
            Answer::Found(json!({"default_branch": "main"})),
        )
        .answer(
            "/repos/example/sample/branches/wave/one",
            branch_answer("wave/one", TIP, true),
        );
    let moved = Fake::default()
        .answer(
            "/repos/example/sample",
            Answer::Found(json!({"default_branch": "main"})),
        )
        .answer(
            "/repos/example/sample/branches/wave/one",
            branch_answer("wave/one", TIP, false),
        )
        .answer(
            "/repos/example/sample/branches/wave/one",
            branch_answer("wave/one", MOVED, false),
        )
        .answer(&compare_path("main"), merged("ahead"))
        .answer(
            "/repos/example/sample/rules/branches/wave/one?per_page=100",
            bot_authority(),
        );
    let ruled = Fake::default()
        .answer(
            "/repos/example/sample",
            Answer::Found(json!({"default_branch": "main"})),
        )
        .answer(
            "/repos/example/sample/branches/wave/one",
            branch_answer("wave/one", TIP, false),
        )
        .answer(&compare_path("main"), merged("ahead"))
        .answer(
            "/repos/example/sample/rules/branches/wave/one?per_page=100",
            Answer::Found(json!([{"type": "pull_request", "ruleset_id": 7}])),
        );
    let default_is_branch = Fake::default().answer(
        "/repos/example/sample",
        Answer::Found(json!({"default_branch": "wave/one"})),
    );
    let cases: Vec<(&str, Fake, &str)> = vec![
        ("default", default_is_branch, "default branch"),
        ("protected", protected, "protected"),
        ("unmerged", remote("main", merged("behind")), "not merged"),
        ("diverged", remote("main", merged("diverged")), "not merged"),
        (
            "merge base elsewhere",
            remote(
                "main",
                Answer::Found(json!({"status": "ahead", "merge_base_commit": {"sha": MOVED}})),
            ),
            "not merged",
        ),
        (
            "comparison 404",
            remote("main", Answer::Missing),
            "cannot compare",
        ),
        (
            "comparison request failed",
            remote("main", Answer::Failed),
            "could not read the comparison",
        ),
        (
            "default named with ..",
            remote("release/..", merged("ahead")),
            "invalid GitHub API path",
        ),
        ("ruled", ruled, "ruleset"),
        ("moved", moved, "moved"),
    ];
    for (case, fake, expected) in cases {
        let error = delete_remote_branch(&fake, &deletion("wave/one"))
            .expect_err(&format!("{case}: the deletion was admitted"));
        let text = format!("{error:#}");
        assert!(text.contains(expected), "{case}: {text}");
        assert!(
            fake.deletes.borrow().is_empty(),
            "{case}: a refused deletion sent DELETE {:?}",
            fake.deletes.borrow()
        );
    }
}

/// The comparison is the only path carrying the `...` separator, percent-encoded so
/// it never holds `..`; its base is the 40-hex tip, so the segment is never a bare
/// dot segment a URL parser would resolve, and a multi-segment default branch keeps
/// its `/` while every other byte of it is encoded as before.
#[test]
fn the_comparison_path_is_the_tip_and_the_encoded_default_branch() {
    let fake = remote("release/v1.0", merged("ahead"));
    delete_remote_branch(&fake, &deletion("wave/one")).unwrap_or_else(|e| panic!("{e:#}"));
    let reads = fake.reads.borrow();
    let comparisons: Vec<&String> = reads.iter().filter(|p| p.contains("/compare/")).collect();
    assert_eq!(
        comparisons,
        vec![&format!(
            "/repos/example/sample/compare/{TIP}%2E%2E%2Erelease/v1.0"
        )]
    );
    for path in reads.iter().chain(fake.deletes.borrow().iter()) {
        assert!(!path.contains(".."), "{path}");
        assert!(
            !path.contains("%2E%2E%2E") || path.contains("/compare/"),
            "the encoded separator outside the comparison: {path}"
        );
        for segment in path.split('?').next().unwrap().split('/') {
            let lower = segment.to_ascii_lowercase();
            assert!(
                !matches!(
                    lower.as_str(),
                    ".." | ".%2e" | "%2e." | "%2e%2e" | "." | "%2e"
                ),
                "a dot segment a URL parser would resolve: {path}"
            );
        }
    }
}

/// `api_path_admitted` is the guard `Github::api_response` held inline before the
/// change: an absolute path with no `..` and no `#`. It refuses everything that
/// guard refused, and nothing more.
#[test]
fn the_extracted_guard_refuses_exactly_what_the_inline_guard_refused() {
    let inline = |path: &str| path.starts_with('/') && !path.contains("..") && !path.contains('#');
    for path in [
        "",
        "/",
        "repos/example/sample",
        "https://api.github.com/repos/example/sample",
        "/repos/example/sample/compare/a...b",
        "/repos/example/sample/compare/a..b",
        "/repos/example/../other",
        "/repos/example/sample/..",
        "/..",
        "/repos/example/sample#fragment",
        "/repos/example/sample/branches/a#b",
        "/repos/example/sample/compare/a%2E%2E%2Eb",
        "/repos/example/sample/git/refs/heads/wave/one",
        "/repos/example/sample/rules/branches/wave/one?per_page=100",
        "//example.com/repos",
        "/repos/example/sample/.../x",
        "/repos/example/sample/x.",
        "/repos/example/sample/.x",
    ] {
        assert_eq!(api_path_admitted(path), inline(path), "{path:?}");
    }
}

// ---------------------------------------------------------------------------
// install
// ---------------------------------------------------------------------------

const INSTALLED: &str = "example/repository";
const OTHER: &str = "example/other";

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

/// A repository with one commit, a private directory with two policies, keys and
/// scanners, and an empty configuration home so no default is ever found.
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
        let fixture = Self {
            repo,
            private: tempfile::tempdir().unwrap(),
            home: tempfile::tempdir().unwrap(),
            baseline,
        };
        for name in ["key", "configured-key", "env-key"] {
            b10x_gates::policy::private_write(&fixture.file(name), &b"0".repeat(64)).unwrap();
        }
        for name in ["gitleaks", "configured-gitleaks", "env-gitleaks"] {
            b10x_gates::policy::private_write(&fixture.file(name), b"not executed").unwrap();
        }
        fixture
    }

    fn file(&self, name: &str) -> PathBuf {
        self.private.path().join(name)
    }

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
        let path = self.file(name);
        b10x_gates::policy::private_write(&path, &serde_json::to_vec(&policy).unwrap()).unwrap();
        fs::canonicalize(path).unwrap()
    }

    fn hooks_directory(&self) -> PathBuf {
        self.repo.path().join(".git/b10x-gates-hooks")
    }

    fn configuration_path(&self) -> PathBuf {
        self.hooks_directory().join("config.json")
    }

    fn configuration(&self) -> Config {
        serde_json::from_slice(&fs::read(self.configuration_path()).unwrap()).unwrap()
    }

    /// The bytes `install` writes, with existing key and scanner paths.
    fn configuration_bytes(&self, repository: &str, policy: &Path) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "repository": repository,
            "policy": policy,
            "key": fs::canonicalize(self.file("configured-key")).unwrap(),
            "scanner": fs::canonicalize(self.file("configured-gitleaks")).unwrap(),
            "previous": {},
            "retired_pre_push_digest": null,
            "installed_version": "0.0.0"
        }))
        .unwrap()
    }

    /// A configuration written by hand (hooks not active: `core.hooksPath` unset).
    fn write_configuration(&self, repository: &str, policy: &Path) {
        fs::create_dir_all(self.hooks_directory()).unwrap();
        fs::set_permissions(self.hooks_directory(), fs::Permissions::from_mode(0o700)).unwrap();
        b10x_gates::policy::private_write(
            &self.configuration_path(),
            &self.configuration_bytes(repository, policy),
        )
        .unwrap();
    }

    /// `b10x-gates install` with only `extra` global flags and `env` set; no other
    /// gates environment and an empty configuration home.
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
}

fn refused(output: &Output) -> String {
    assert!(
        !output.status.success(),
        "install was admitted: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// `untrusted-configuration`: a configuration that is a symlink to an owner-only file
/// with valid content is refused naming the symlink, and nothing is written.
#[test]
fn install_refuses_a_symlinked_installed_configuration() {
    let f = Fixture::new();
    let policy = f.write_policy("policy.json", &[INSTALLED]);
    let target = f.file("elsewhere.json");
    b10x_gates::policy::private_write(&target, &f.configuration_bytes(INSTALLED, &policy)).unwrap();
    fs::create_dir_all(f.hooks_directory()).unwrap();
    fs::set_permissions(f.hooks_directory(), fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&target, f.configuration_path()).unwrap();
    let stderr = refused(&f.install(&[], &[]));
    assert!(stderr.contains("symlink"), "{stderr}");
    assert!(stderr.contains("config.json"), "{stderr}");
    assert!(
        fs::symlink_metadata(f.configuration_path())
            .unwrap()
            .file_type()
            .is_symlink(),
        "install replaced the refused configuration"
    );
}

/// `untrusted-configuration`: an owner-only configuration in a hooks directory others
/// can write is refused with its cause, never read as trusted.
#[test]
fn install_refuses_a_configuration_in_a_directory_others_can_write() {
    let f = Fixture::new();
    let policy = f.write_policy("policy.json", &[INSTALLED]);
    f.write_configuration(INSTALLED, &policy);
    fs::set_permissions(f.hooks_directory(), fs::Permissions::from_mode(0o777)).unwrap();
    let stderr = refused(&f.install(&[], &[]));
    fs::set_permissions(f.hooks_directory(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(stderr.contains("writable by group or others"), "{stderr}");
}

/// flag > environment > installed configuration: `B10X_GATES_KEY` and
/// `B10X_GATES_GITLEAKS` win over the configured key and scanner, as
/// `B10X_GATES_POLICY` does.
#[test]
fn install_key_and_scanner_environment_win_over_the_installed_configuration() {
    let f = Fixture::new();
    let policy = f.write_policy("policy.json", &[INSTALLED]);
    f.write_configuration(INSTALLED, &policy);
    let key = f.file("env-key");
    let scanner = f.file("env-gitleaks");
    succeeded(&f.install(
        &[],
        &[
            ("B10X_GATES_KEY", key.as_path()),
            ("B10X_GATES_GITLEAKS", scanner.as_path()),
        ],
    ));
    let written = f.configuration();
    assert_eq!(written.repository, INSTALLED);
    assert_eq!(written.policy, policy);
    assert_eq!(written.key, fs::canonicalize(&key).unwrap());
    assert_eq!(written.scanner, fs::canonicalize(&scanner).unwrap());
}

/// RED. A configuration is trusted only for the repository it names. `install
/// --repository example/repository` in a checkout whose installed configuration names
/// `example/other` (hooks not active, so `hooks::install`'s own mismatch check does
/// not run) must not take that other repository's policy, key or scanner: with no
/// policy flag, environment or default it is refused, as a first install would be.
/// Today the other repository's configured policy, key and scanner are installed for
/// `example/repository`.
#[test]
fn install_takes_nothing_from_a_configuration_naming_another_repository() {
    let f = Fixture::new();
    let shared = f.write_policy("shared.json", &[INSTALLED, OTHER]);
    f.write_configuration(OTHER, &shared);
    let output = f.install(&["--repository", INSTALLED], &[]);
    if output.status.success() {
        let written = f.configuration();
        assert!(
            written.policy != shared
                && written.key != fs::canonicalize(f.file("configured-key")).unwrap()
                && written.scanner != fs::canonicalize(f.file("configured-gitleaks")).unwrap(),
            "install for {INSTALLED} took the policy, key and scanner of the configuration \
             naming {OTHER}: policy {}, key {}, scanner {}",
            written.policy.display(),
            written.key.display(),
            written.scanner.display()
        );
    }
}
