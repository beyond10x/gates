use b10x_gates::{
    BOT_EMAIL, BOT_NAME, digest,
    evidence::{self, Receipt},
    git::{Candidate, Git, Unit},
    policy::{Exception, Policy, Repository, Signer},
    scan::{self, Gitleaks, SecretFinding, SecretScanner},
};
use ed25519_dalek::{Signer as _, SigningKey};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
use tempfile::TempDir;

const REPOSITORY: &str = "example/repository";

#[derive(Default)]
struct CountScanner {
    calls: usize,
}
impl SecretScanner for CountScanner {
    fn scan(&mut self, _: &[Unit]) -> anyhow::Result<Vec<SecretFinding>> {
        self.calls += 1;
        Ok(vec![])
    }
}

struct Fixture {
    dir: TempDir,
    baseline: String,
    policy: Policy,
    key: SigningKey,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        git(
            dir.path(),
            &[
                "-c",
                "init.templateDir=",
                "init",
                "-q",
                "--initial-branch=main",
            ],
        );
        fs::write(dir.path().join("readme"), "initial safe bytes\n").unwrap();
        git(dir.path(), &["add", "."]);
        git(dir.path(), &["commit", "-qm", "initial"]);
        let baseline = git(dir.path(), &["rev-parse", "HEAD"]);
        let key = SigningKey::from_bytes(&[17; 32]);
        let policy = Policy {
            version: 1,
            nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
            forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
            repositories: BTreeMap::from([(
                REPOSITORY.into(),
                Repository {
                    id: "123".into(),
                    baseline: baseline.clone(),
                },
            )]),
            signers: BTreeMap::from([(
                "fixture-key".into(),
                Signer {
                    public_key: hex::encode(key.verifying_key().to_bytes()),
                    repositories: vec![REPOSITORY.into()],
                },
            )]),
            exceptions: vec![],
        };
        Self {
            dir,
            baseline,
            policy,
            key,
        }
    }
    fn commit(&self, path: &str, bytes: &[u8], message: &str) -> String {
        let file = self.dir.path().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
        git(self.dir.path(), &["add", "--", path]);
        git(self.dir.path(), &["commit", "-qm", message]);
        git(self.dir.path(), &["rev-parse", "HEAD"])
    }
    fn candidate(&self, head: &str) -> Candidate {
        Git::new(self.dir.path())
            .unwrap()
            .candidate(&self.policy, REPOSITORY, head, &[])
            .unwrap()
    }
}

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

fn unit(bytes: impl AsRef<[u8]>) -> Unit {
    Unit {
        location: "file:sample".into(),
        bytes: bytes.as_ref().into(),
        workflow: false,
    }
}
fn home() -> String {
    ["", "home", "fixture-person"].join("/")
}

#[test]
fn index_is_scanned_independently_of_unstaged_content() {
    let f = Fixture::new();
    let path = f.dir.path().join("readme");
    fs::write(&path, home()).unwrap();
    git(f.dir.path(), &["add", "readme"]);
    fs::write(&path, "clean unstaged content").unwrap();
    let git = Git::new(f.dir.path()).unwrap();
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        &git.staged().unwrap(),
        &mut CountScanner::default(),
    )
    .unwrap();
    assert_eq!(report.findings[0].rule, "personal-paths");
    git.read(&["add", "readme"]).unwrap();
    fs::write(&path, home()).unwrap();
    assert!(
        scan::run(
            &f.policy,
            REPOSITORY,
            &git.staged().unwrap(),
            &mut CountScanner::default()
        )
        .unwrap()
        .findings
        .is_empty()
    );
}

#[test]
fn an_intermediate_violation_cannot_be_hidden_by_a_later_deletion() {
    let f = Fixture::new();
    let bad = f.commit("journal", home().as_bytes(), "add journal");
    git(f.dir.path(), &["rm", "journal"]);
    git(f.dir.path(), &["commit", "-qm", "remove journal"]);
    let head = git(f.dir.path(), &["rev-parse", "HEAD"]);
    let candidate = f.candidate(&head);
    assert!(candidate.binding.commits.contains(&bad));
    assert!(
        evidence::check(&f.policy, &candidate, &f.key, &mut CountScanner::default())
            .unwrap_err()
            .to_string()
            .contains("common checks failed")
    );
}

#[test]
fn filenames_messages_author_and_committer_are_scanned() {
    let f = Fixture::new();
    let denied = f.policy.forbidden_literals[0].clone();
    let head = f.commit(&denied, b"safe", &denied);
    let candidate = f.candidate(&head);
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut CountScanner::default(),
    )
    .unwrap();
    assert!(
        report
            .findings
            .iter()
            .any(|v| v.location.starts_with("filename:"))
    );
    assert!(
        report
            .findings
            .iter()
            .any(|v| v.location.starts_with("commit:"))
    );
    let tree = git(f.dir.path(), &["rev-parse", "HEAD^{tree}"]);
    let raw = format!(
        "tree {tree}\nparent {head}\nauthor {denied} <fixture@example.invalid> 1 +0000\ncommitter {denied} <fixture@example.invalid> 1 +0000\n\nmessage\n"
    );
    let mut child = Command::new("git")
        .current_dir(f.dir.path())
        .args(["hash-object", "-t", "commit", "-w", "--stdin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(raw.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    let oid = String::from_utf8(output.stdout).unwrap();
    let candidate = f.candidate(oid.trim());
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut CountScanner::default(),
    )
    .unwrap();
    assert!(report.results["private-identifiers"].findings >= 4);
}

#[test]
fn annotated_tag_messages_identities_and_names_are_bound() {
    let f = Fixture::new();
    let head = f.commit("readme", b"next", "next");
    let denied = &f.policy.forbidden_literals[0];
    git(f.dir.path(), &["tag", "-a", denied, "-m", denied]);
    let git = Git::new(f.dir.path()).unwrap();
    let candidate = git
        .candidate(&f.policy, REPOSITORY, &head, std::slice::from_ref(denied))
        .unwrap();
    assert_eq!(candidate.binding.tags.len(), 1);
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut CountScanner::default(),
    )
    .unwrap();
    assert!(report.results["private-identifiers"].findings >= 2);
    assert!(
        report
            .findings
            .iter()
            .any(|v| v.location.starts_with("tag:"))
    );
    let clean = f.candidate(&head);
    let receipt = evidence::check(&f.policy, &clean, &f.key, &mut CountScanner::default()).unwrap();
    assert!(evidence::verify(&f.policy, &candidate, &receipt).is_err());
}

#[test]
fn bare_home_directories_fail_and_portable_placeholders_pass() {
    let f = Fixture::new();
    for path in [
        home(),
        ["", "Users", "fixture-person"].join("/"),
        ["C:", "Users", "fixture-person"].join("\\"),
        ["D:", "Users", "fixture-person"].join("/"),
    ] {
        let report = scan::run(
            &f.policy,
            REPOSITORY,
            &[unit(path)],
            &mut CountScanner::default(),
        )
        .unwrap();
        assert_eq!(report.results["personal-paths"].findings, 1);
    }
    for path in [
        "$HOME",
        "${HOME}/cache",
        "$XDG_CONFIG_HOME/application",
        "${XDG_CACHE_HOME}/build",
        "/home/$USER",
        "/home/<user>",
        "https://api.github.com/users/service",
    ] {
        assert!(
            scan::run(
                &f.policy,
                REPOSITORY,
                &[unit(path)],
                &mut CountScanner::default()
            )
            .unwrap()
            .findings
            .is_empty(),
            "placeholder or URL refused"
        );
    }
}

#[test]
fn candidate_ignore_files_comments_and_unbounded_exceptions_do_not_disable_rules() {
    let f = Fixture::new();
    let input = format!("{} # gitleaks:allow\n", f.policy.forbidden_literals[0]);
    let head = f.commit(".gitleaksignore", input.as_bytes(), "attempt ignore");
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        &f.candidate(&head).units,
        &mut CountScanner::default(),
    )
    .unwrap();
    assert_eq!(report.results["private-identifiers"].findings, 1);
    let mut policy = f.policy.clone();
    policy.exceptions.push(Exception {
        repository: REPOSITORY.into(),
        rule: "*".into(),
        location: "*".into(),
        content_sha256: "*".into(),
        line: 0,
    });
    assert!(policy.validate().is_err());
    let u = unit(input);
    policy.exceptions = vec![Exception {
        repository: REPOSITORY.into(),
        rule: "private-identifiers".into(),
        location: u.location.clone(),
        content_sha256: digest(u.bytes.split(|b| *b == b'\n').next().unwrap()),
        line: 1,
    }];
    assert!(
        scan::run(
            &policy,
            REPOSITORY,
            std::slice::from_ref(&u),
            &mut CountScanner::default()
        )
        .unwrap()
        .findings
        .is_empty()
    );
    let mut changed = u;
    changed.bytes.insert(0, b'!');
    assert!(
        !scan::run(
            &policy,
            REPOSITORY,
            &[changed],
            &mut CountScanner::default()
        )
        .unwrap()
        .findings
        .is_empty()
    );
}

#[test]
fn hostile_fork_content_is_read_as_data_and_symlinks_are_not_followed() {
    let f = Fixture::new();
    let sentinel = f.dir.path().join("executed");
    let script = format!("#!/bin/sh\ntouch '{}'\n", sentinel.display());
    f.commit(".gitmodules", script.as_bytes(), "hostile modules");
    f.commit(
        ".gitattributes",
        b"* filter=hostile\n",
        "hostile attributes",
    );
    f.commit("Cargo.toml", script.as_bytes(), "hostile build");
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&sentinel, f.dir.path().join("link")).unwrap();
        git(f.dir.path(), &["add", "link"]);
        git(f.dir.path(), &["commit", "-qm", "symlink"]);
    }
    let head = git(f.dir.path(), &["rev-parse", "HEAD"]);
    let candidate = f.candidate(&head);
    let _ = scan::run(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut CountScanner::default(),
    )
    .unwrap();
    assert!(!sentinel.exists());
}

#[test]
fn valid_reuse_performs_zero_scanner_invocations_even_with_no_scanner_available() {
    let f = Fixture::new();
    let head = f.commit("readme", b"safe change", "safe");
    let candidate = f.candidate(&head);
    let receipt =
        evidence::check(&f.policy, &candidate, &f.key, &mut CountScanner::default()).unwrap();
    struct Unavailable;
    impl SecretScanner for Unavailable {
        fn scan(&mut self, _: &[Unit]) -> anyhow::Result<Vec<SecretFinding>> {
            panic!("valid reuse invoked a scanner")
        }
    }
    assert!(
        evidence::reuse_or_scan(&f.policy, &candidate, Some(&receipt), &mut Unavailable).unwrap()
    );
}

#[test]
fn receipt_rejects_tampering_wrong_repository_signer_policy_and_incomplete_results() {
    let f = Fixture::new();
    let head = f.commit("readme", b"safe change", "safe");
    let candidate = f.candidate(&head);
    let receipt =
        evidence::check(&f.policy, &candidate, &f.key, &mut CountScanner::default()).unwrap();
    let mut invalid = receipt.clone();
    invalid.signature.replace_range(..2, "00");
    assert!(evidence::verify(&f.policy, &candidate, &invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.payload.binding.repository_id = "999".into();
    assert!(evidence::verify(&f.policy, &candidate, &invalid).is_err());
    let mut invalid = receipt.clone();
    invalid.payload.signer = "untrusted".into();
    assert!(evidence::verify(&f.policy, &candidate, &invalid).is_err());
    let mut policy = f.policy.clone();
    policy.nonce.push('x');
    assert!(evidence::verify(&policy, &candidate, &receipt).is_err());
    let mut invalid = receipt.clone();
    invalid.payload.results.remove("secrets");
    resign(&mut invalid, &f.key);
    assert!(
        evidence::verify(&f.policy, &candidate, &invalid)
            .unwrap_err()
            .to_string()
            .contains("incomplete")
    );
    let key = SigningKey::from_bytes(&[18; 32]);
    let mut invalid = receipt.clone();
    resign(&mut invalid, &key);
    assert!(
        evidence::verify(&f.policy, &candidate, &invalid)
            .unwrap_err()
            .to_string()
            .contains("signature")
    );
    let mut scanner = CountScanner::default();
    assert!(!evidence::reuse_or_scan(&f.policy, &candidate, Some(&invalid), &mut scanner).unwrap());
    assert_eq!(scanner.calls, 1);
}

fn resign(receipt: &mut Receipt, key: &SigningKey) {
    let mut message = b"b10x.gates.receipt/1\0".to_vec();
    message.extend(serde_json::to_vec(&receipt.payload).unwrap());
    receipt.signature = hex::encode(key.sign(&message).to_bytes());
}

#[test]
fn rebase_and_source_changes_invalidate_receipts() {
    let f = Fixture::new();
    let head = f.commit("readme", b"safe change", "safe");
    let receipt = evidence::check(
        &f.policy,
        &f.candidate(&head),
        &f.key,
        &mut CountScanner::default(),
    )
    .unwrap();
    git(
        f.dir.path(),
        &["commit", "--amend", "-qm", "rewritten message"],
    );
    let rewritten = git(f.dir.path(), &["rev-parse", "HEAD"]);
    assert!(evidence::verify(&f.policy, &f.candidate(&rewritten), &receipt).is_err());
    let changed = f.commit("readme", b"new source", "another change");
    assert!(evidence::verify(&f.policy, &f.candidate(&changed), &receipt).is_err());
}

#[test]
fn workflows_require_immutable_action_revisions_and_explicit_permissions() {
    let f = Fixture::new();
    let text = "name: CI\non: push\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@main\n";
    let u = Unit {
        workflow: true,
        ..unit(text)
    };
    let report = scan::run(&f.policy, REPOSITORY, &[u], &mut CountScanner::default()).unwrap();
    assert_eq!(report.results["workflow-pins"].findings, 1);
    assert_eq!(report.results["workflow-permissions"].findings, 1);
    let fixed = text
        .replace("jobs:", "permissions:\n  contents: read\njobs:")
        .replace("@main", &format!("@{}", "a".repeat(40)));
    assert!(
        scan::run(
            &f.policy,
            REPOSITORY,
            &[Unit {
                workflow: true,
                ..unit(fixed)
            }],
            &mut CountScanner::default()
        )
        .unwrap()
        .findings
        .is_empty()
    );
}

#[test]
fn actual_gitleaks_cannot_be_disabled_by_candidate_config_or_comments_and_output_is_redacted() {
    let path = std::env::var_os("B10X_GATES_GITLEAKS")
        .expect("set B10X_GATES_GITLEAKS to the pinned binary; this scanner test must not skip");
    let f = Fixture::new();
    let token = format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let input = format!("token = '{token}' # gitleaks:allow\n");
    let units = [
        unit(input),
        Unit {
            location: "file:.gitleaks.toml".into(),
            ..unit("[allowlist]\nregexes = ['.*']\n")
        },
    ];
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        &units,
        &mut Gitleaks {
            binary: path.into(),
        },
    )
    .unwrap();
    assert!(report.results["secrets"].findings > 0);
    let serialized = serde_json::to_string(&report.findings).unwrap();
    assert!(!serialized.contains(&token));
    assert!(
        !report
            .require_success()
            .unwrap_err()
            .to_string()
            .contains(&token)
    );
}

#[test]
fn a_changed_baseline_and_history_replacement_are_refused() {
    let f = Fixture::new();
    let head = f.commit("readme", b"safe change", "safe");
    fs::create_dir_all(f.dir.path().join(".git/info")).unwrap();
    fs::write(f.dir.path().join(".git/info/grafts"), &f.baseline).unwrap();
    assert!(
        Git::new(f.dir.path())
            .err()
            .unwrap()
            .to_string()
            .contains("grafted")
    );
    fs::remove_file(f.dir.path().join(".git/info/grafts")).unwrap();
    let receipt = evidence::check(
        &f.policy,
        &f.candidate(&head),
        &f.key,
        &mut CountScanner::default(),
    )
    .unwrap();
    let mut policy = f.policy.clone();
    policy.repositories.get_mut(REPOSITORY).unwrap().baseline = head.clone();
    let candidate = Git::new(f.dir.path())
        .unwrap()
        .candidate(&policy, REPOSITORY, &head, &[])
        .unwrap();
    assert!(evidence::verify(&policy, &candidate, &receipt).is_err());
}

#[test]
fn installed_hooks_preserve_worktree_hooks_and_scan_after_existing_mutations_without_atlas() {
    let f = Fixture::new();
    let private = tempfile::tempdir().unwrap();
    let policy_path = private.path().join("policy.json");
    let key_path = private.path().join("key");
    b10x_gates::policy::private_write(&policy_path, &serde_json::to_vec(&f.policy).unwrap())
        .unwrap();
    b10x_gates::policy::private_write(&key_path, hex::encode(f.key.to_bytes()).as_bytes()).unwrap();
    let hooks = f.dir.path().join(".git/hooks");
    fs::create_dir_all(&hooks).unwrap();
    let source = private.path().join("fixture.rs");
    fs::write(&source, r#"
        use std::{env, fs, io::Write, process::Command};
        fn main() {
            let executable = env::args().next().unwrap();
            let name = std::path::Path::new(&executable).file_name().unwrap().to_str().unwrap();
            if name == "pre-commit" {
                if let Ok(bytes) = env::var("FIXTURE_INSERT") {
                    fs::write("inserted", bytes).unwrap();
                    assert!(Command::new("git").args(["add", "inserted"]).status().unwrap().success());
                }
            } else if name == "commit-msg" {
                if let Ok(bytes) = env::var("FIXTURE_MESSAGE") {
                    let mut file = fs::OpenOptions::new().append(true).open(env::args().nth(1).unwrap()).unwrap();
                    writeln!(file, "{bytes}").unwrap();
                }
            } else { fs::write("preserved-hook-ran", "yes").unwrap(); }
        }
    "#).unwrap();
    let binary = private.path().join("fixture");
    assert!(
        Command::new("rustc")
            .arg(&source)
            .arg("-o")
            .arg(&binary)
            .status()
            .unwrap()
            .success()
    );
    for name in ["pre-commit", "commit-msg", "post-checkout", "pre-push"] {
        fs::copy(&binary, hooks.join(name)).unwrap();
    }
    let old_digest = digest(&fs::read(&binary).unwrap());
    let scanner = std::env::var_os("B10X_GATES_GITLEAKS").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .args(["--repo"])
        .arg(f.dir.path())
        .args(["--repository", REPOSITORY, "--policy"])
        .arg(&policy_path)
        .arg("--key")
        .arg(&key_path)
        .arg("--gitleaks")
        .arg(&scanner)
        .args(["install", "--retire-pre-push-sha256", &old_digest])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let commit = |insert: &str, message: &str| {
        Command::new("git")
            .current_dir(f.dir.path())
            .args(["commit", "--allow-empty", "-m", "safe message"])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", BOT_NAME)
            .env("GIT_AUTHOR_EMAIL", BOT_EMAIL)
            .env("GIT_COMMITTER_NAME", BOT_NAME)
            .env("GIT_COMMITTER_EMAIL", BOT_EMAIL)
            .env(
                "B10X_ATLAS_CHECKOUT",
                private.path().join("unavailable-atlas"),
            )
            .env("FIXTURE_INSERT", insert)
            .env("FIXTURE_MESSAGE", message)
            .output()
            .unwrap()
    };
    let denied = &f.policy.forbidden_literals[0];
    let bad_index = commit(denied, "safe");
    assert!(!bad_index.status.success());
    assert!(!String::from_utf8_lossy(&bad_index.stderr).contains(denied));
    let bad_message = commit("safe", denied);
    assert!(!bad_message.status.success());
    assert!(!String::from_utf8_lossy(&bad_message.stderr).contains(denied));
    let good = commit("safe", "safe");
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    git(f.dir.path(), &["checkout", "-qb", "fixture-branch"]);
    assert!(f.dir.path().join("preserved-hook-ran").exists());
    let installed = f.dir.path().join(".git/b10x-gates-hooks");
    let config: b10x_gates::hooks::Config =
        serde_json::from_slice(&fs::read(installed.join("config.json")).unwrap()).unwrap();
    assert!(!config.previous.contains_key("pre-push"));
    assert!(config.previous.contains_key("post-checkout"));
    assert_eq!(
        config.retired_pre_push_digest.as_deref(),
        Some(old_digest.as_str())
    );
    let receipt = private.path().join("receipt.json");
    let checked = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .arg("--repo")
        .arg(f.dir.path())
        .args(["--repository", REPOSITORY, "--policy"])
        .arg(&policy_path)
        .arg("--key")
        .arg(&key_path)
        .arg("--gitleaks")
        .arg(&scanner)
        .args(["check", "--receipt"])
        .arg(&receipt)
        .env(
            "B10X_ATLAS_CHECKOUT",
            private.path().join("unavailable-atlas"),
        )
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let verified = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .arg("--repo")
        .arg(f.dir.path())
        .args(["--repository", REPOSITORY, "--policy"])
        .arg(&policy_path)
        .arg("--gitleaks")
        .arg(private.path().join("missing-scanner"))
        .args(["verify", "--receipt"])
        .arg(&receipt)
        .env(
            "B10X_ATLAS_CHECKOUT",
            private.path().join("unavailable-atlas"),
        )
        .output()
        .unwrap();
    assert!(verified.status.success());
    assert!(String::from_utf8_lossy(&verified.stdout).contains("scanner_invocations=0"));
}
