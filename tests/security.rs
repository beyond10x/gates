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
            forbidden_patterns: vec![],
            allow_patterns: vec![],
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
        inherited: None,
    }
}
fn unit_with(bytes: impl AsRef<[u8]>, inherited: Option<String>) -> Unit {
    Unit {
        inherited: inherited.map(String::into_bytes),
        ..unit(bytes)
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
    assert!(
        Git::new(f.dir.path())
            .unwrap()
            .candidate(&f.policy, REPOSITORY, oid.trim(), &[])
            .is_err()
    );
    // Privacy scanning remains independently covered even when identity admission refuses first.
    let mut units = candidate.units;
    units.push(Unit {
        location: format!("commit:{}", oid.trim()),
        bytes: raw.into_bytes(),
        workflow: false,
        inherited: None,
    });
    let report = scan::run(&f.policy, REPOSITORY, &units, &mut CountScanner::default()).unwrap();
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
    for field in ["GIT_AUTHOR_EMAIL", "GIT_COMMITTER_EMAIL"] {
        let refused = Command::new("git")
            .current_dir(f.dir.path())
            .args(["commit", "--allow-empty", "-m", "safe identity fixture"])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", BOT_NAME)
            .env("GIT_AUTHOR_EMAIL", BOT_EMAIL)
            .env("GIT_COMMITTER_NAME", BOT_NAME)
            .env("GIT_COMMITTER_EMAIL", BOT_EMAIL)
            .env(field, "person@example.invalid")
            .output()
            .unwrap();
        assert!(
            !refused.status.success(),
            "local identity guard must refuse"
        );
        assert!(
            String::from_utf8_lossy(&refused.stderr).contains("exact bot author and committer")
        );
        assert!(!String::from_utf8_lossy(&refused.stderr).contains("person@example.invalid"));
    }
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
    assert_eq!(config.installed_version, b10x_gates::VERSION);
    // One binary a repository. The 13 hook names are links to it, so `argv[0]` still
    // selects the hook and the inode still pins the exact binary.
    {
        use std::os::unix::fs::MetadataExt;
        let pinned = fs::metadata(installed.join("b10x-gates")).unwrap().ino();
        for hook in [
            "pre-commit",
            "commit-msg",
            "pre-push",
            "post-checkout",
            "post-commit",
            "post-merge",
            "pre-rebase",
            "prepare-commit-msg",
            "post-rewrite",
            "applypatch-msg",
            "pre-applypatch",
            "post-applypatch",
            "reference-transaction",
        ] {
            assert_eq!(
                fs::metadata(installed.join(hook)).unwrap().ino(),
                pinned,
                "{hook} is a copy, not a link"
            );
        }
        let footprint: u64 = fs::read_dir(&installed)
            .unwrap()
            .map(|e| {
                let meta = e.unwrap().metadata().unwrap();
                if meta.ino() == pinned { 0 } else { meta.len() }
            })
            .sum::<u64>()
            + fs::metadata(installed.join("b10x-gates")).unwrap().len();
        let one = fs::metadata(installed.join("b10x-gates")).unwrap().len();
        assert!(
            footprint < one + 64 * 1024,
            "installed footprint {footprint} exceeds one binary of {one}"
        );
    }
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

fn identity_commit(f: &Fixture, parents: &[&str], author: &str, committer: &str) -> String {
    let tree = git(f.dir.path(), &["rev-parse", "HEAD^{tree}"]);
    let parents = parents
        .iter()
        .map(|p| format!("parent {p}\n"))
        .collect::<String>();
    let raw = format!(
        "tree {tree}\n{parents}author {author} 1 +0000\ncommitter {committer} 1 +0000\n\nfixture\n"
    );
    let mut child = Command::new("git")
        .current_dir(f.dir.path())
        .args([
            "hash-object",
            "--literally",
            "-t",
            "commit",
            "-w",
            "--stdin",
        ])
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
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap().trim().into()
}

#[test]
fn authorship_admits_exact_automation_and_keeps_direct_delivery_strict() {
    let f = Fixture::new();
    let bot = format!("{BOT_NAME} <{BOT_EMAIL}>");
    let actions = format!(
        "{} <{}>",
        b10x_gates::ACTIONS_NAME,
        b10x_gates::ACTIONS_EMAIL
    );
    for (author, committer) in [
        (&bot, &bot),
        (&actions, &actions),
        (&bot, &"GitHub <noreply@github.com>".into()),
    ] {
        let head = identity_commit(&f, &[&f.baseline], author, committer);
        let candidate = f.candidate(&head);
        let mut scanner = CountScanner::default();
        let receipt = evidence::check(&f.policy, &candidate, &f.key, &mut scanner).unwrap();
        assert_eq!(receipt.payload.results["commit-authorship"].inspected, 1);
        assert!(
            evidence::reuse_or_scan(&f.policy, &candidate, Some(&receipt), &mut scanner).unwrap()
        );
        assert_eq!(scanner.calls, 1, "receipt reuse does not scan");
        assert_eq!(
            Git::new(f.dir.path()).unwrap().verify_bot(&[head]).is_ok(),
            author == &bot && committer == &bot
        );
    }
}

#[test]
fn authorship_refuses_human_spoofed_and_duplicate_raw_authors() {
    let f = Fixture::new();
    let bot = format!("{BOT_NAME} <{BOT_EMAIL}>");
    for author in [
        "Fixture Person <person@example.invalid>".to_owned(),
        format!("Fixture Person <{BOT_EMAIL}>"),
        format!("{BOT_NAME} <person@example.invalid>"),
        "github-actions[bot] <actions@example.invalid>".into(),
        "other[bot] <other@example.invalid>".into(),
        format!("{bot} 1 +0000\nauthor {bot}"),
    ] {
        let head = identity_commit(&f, &[&f.baseline], &author, &bot);
        fs::write(
            f.dir.path().join(".mailmap"),
            format!("{bot} Fixture Person <person@example.invalid>\n"),
        )
        .unwrap();
        assert!(
            Git::new(f.dir.path())
                .unwrap()
                .candidate(&f.policy, REPOSITORY, &head, &[])
                .is_err(),
            "raw author must refuse"
        );
    }
}

#[test]
fn authorship_refuses_bad_intermediate_and_merged_side_commits() {
    let f = Fixture::new();
    let bot = format!("{BOT_NAME} <{BOT_EMAIL}>");
    let bad = identity_commit(
        &f,
        &[&f.baseline],
        "Fixture Person <person@example.invalid>",
        &bot,
    );
    let clean = identity_commit(&f, &[&f.baseline], &bot, &bot);
    for parents in [vec![bad.as_str()], vec![clean.as_str(), bad.as_str()]] {
        let head = identity_commit(&f, &parents, &bot, &bot);
        assert!(
            Git::new(f.dir.path())
                .unwrap()
                .candidate(&f.policy, REPOSITORY, &head, &[])
                .is_err()
        );
    }
}

// --- private rules: the shapes a literal is smuggled in, and the shapes that are admitted ---

/// A policy carrying only rule content, for matcher tests that touch no repository.
fn rules(patterns: &[&str], allow: &[&str]) -> Policy {
    Policy {
        version: 2,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: patterns.iter().map(|v| (*v).to_owned()).collect(),
        // An allowance must name what it admits. A fixture that does not care where
        // the boundary falls admits its whole match; one that does places the group
        // itself.
        allow_patterns: allow
            .iter()
            .map(|v| {
                if v.contains("(?P<admit>") {
                    (*v).to_owned()
                } else {
                    format!("(?P<admit>{v})")
                }
            })
            .collect(),
        repositories: BTreeMap::new(),
        signers: BTreeMap::new(),
        exceptions: vec![],
    }
}

fn breaks(policy: &Policy, line: &str) -> Vec<&'static str> {
    scan::Matchers::build(policy).unwrap().line(line.as_bytes())
}

#[test]
fn home_paths_are_caught_in_every_delimiter_this_estate_writes() {
    let policy = rules(&[], &[]);
    let path = home();
    let caught = [
        format!("the tree is at {path}/beyond10x"),
        format!("{path}/beyond10x"),
        format!("ROOT={path}/beyond10x"),
        format!("[the tree]({path}/beyond10x)"),
        // The four the old boundary class refused to open on.
        format!("run `{path}/beyond10x/bin` first"),
        format!("| tree | {path}/beyond10x |"),
        format!("|{path}/beyond10x|"),
        format!("see *{path}/beyond10x* above"),
        format!("file://{path}/beyond10x"),
        format!("\"{path}/beyond10x\""),
    ];
    for line in caught {
        assert!(
            breaks(&policy, &line).contains(&"personal-paths"),
            "missed: {line}"
        );
    }
}

#[test]
fn a_path_that_only_contains_the_word_home_is_not_a_personal_path() {
    let policy = rules(&[], &[]);
    for line in [
        "https://example.invalid/home/index.html",
        "../home/fixture-person",
        "src/home/mod.rs",
        "/usr/home-brew/bin",
    ] {
        assert!(
            !breaks(&policy, line).contains(&"personal-paths"),
            "false positive: {line}"
        );
    }
}

#[test]
fn patterns_express_what_an_escaped_literal_cannot() {
    let policy = rules(
        &[r"fixture[\W_]{0,3}(alpha|beta)", r"(?:^|\W)surname(?:\W|$)"],
        &[],
    );
    for line in [
        "fixture-alpha",
        "Fixture_Beta",
        "fixture  alpha",
        "FIXTUREALPHA",
        "the surname stands alone",
        "surname@example.invalid",
        "Surname, capitalised",
    ] {
        assert_eq!(
            breaks(&policy, line),
            vec!["private-identifiers"],
            "missed: {line}"
        );
    }
    assert!(breaks(&policy, "a surnamed thing").is_empty());
}

#[test]
fn an_allowance_admits_only_what_its_match_contains() {
    let literal = ["synthetic", "restricted", "identifier"].join("-");
    let policy = rules(&[], &[r"https://github\.com/[a-z0-9._-]+/[a-z0-9._-]+"]);
    // The citation itself is admitted.
    assert!(breaks(&policy, &format!("https://github.com/{literal}/thing")).is_empty());
    assert!(
        breaks(
            &policy,
            &format!("git = \"https://github.com/{literal}/thing\"")
        )
        .is_empty()
    );
    // The same name in prose on the same line is still refused: the allowance is a
    // span, never the line it sits on.
    assert_eq!(
        breaks(
            &policy,
            &format!("https://github.com/{literal}/thing is run by {literal}")
        ),
        vec!["private-identifiers"]
    );
    assert_eq!(
        breaks(&policy, &format!("{literal} ships it")),
        vec!["private-identifiers"]
    );
}

#[test]
fn an_allowance_cannot_be_stretched_over_an_adjacent_use() {
    // A greedy allowance that runs to end of line would swallow the prose use; the
    // rule under test is that containment is computed per occurrence, not per line.
    let literal = ["synthetic", "restricted", "identifier"].join("-");
    let policy = rules(&[], &[r"https://github\.com/[a-z0-9._-]+/[a-z0-9._-]+"]);
    let line = format!("{literal} at https://github.com/{literal}/thing");
    assert_eq!(breaks(&policy, &line), vec!["private-identifiers"]);
}

#[test]
fn text_reports_every_line_that_breaks_a_rule() {
    let literal = ["synthetic", "restricted", "identifier"].join("-");
    let policy = rules(&[], &[]);
    let body = format!("clean line\n{literal}\nalso clean\n{}/x\n", home());
    let broken = scan::Matchers::build(&policy)
        .unwrap()
        .text(body.as_bytes());
    assert_eq!(
        broken,
        vec![(2, "private-identifiers"), (4, "personal-paths")]
    );
}

#[test]
fn a_policy_whose_pattern_does_not_compile_is_refused_at_load() {
    let mut policy = rules(&["fixture(unclosed"], &[]);
    assert!(policy.validate().is_err());
    policy = rules(&[], &["fixture(unclosed"]);
    assert!(policy.validate().is_err());
}

#[test]
fn pattern_rules_require_the_second_policy_version() {
    let mut policy = rules(&["fixture-alpha"], &[]);
    policy.version = 1;
    assert!(policy.validate().is_err());
}

// --- adversarial pass: evasion of the private rules ---
//
// Every case below is a smuggling attempt against the synthetic policy only. Tests
// that pass record a defence that holds; tests marked `#[ignore]` are live defects
// and each names the defect in its comment.

fn literal() -> String {
    ["synthetic", "restricted", "identifier"].join("-")
}

fn breaks_bytes(policy: &Policy, line: &[u8]) -> Vec<&'static str> {
    scan::Matchers::build(policy).unwrap().line(line)
}

#[test]
fn a_literal_survives_every_delimiter_this_estate_writes() {
    let policy = rules(&[], &[]);
    let l = literal();
    for line in [
        format!("`{l}`"),
        format!("| owner | {l} |"),
        format!("|{l}|"),
        format!("*{l}*"),
        format!("_{l}_"),
        format!("<{l}>"),
        format!("[{l}]"),
        format!("({l})"),
        format!("\"{l}\""),
        format!("'{l}'"),
        format!("file:///srv/{l}/x"),
        // A CRLF file reaches the matcher with the CR still attached to the line.
        format!("{l}\r"),
        format!("a\r{l}\r"),
        l.to_uppercase(),
        "SyNtHeTiC-ResTricTed-IdEnTiFiEr".into(),
    ] {
        assert_eq!(
            breaks(&policy, &line),
            vec!["private-identifiers"],
            "missed: {line:?}"
        );
    }
}

#[test]
fn case_insensitivity_is_unicode_simple_folding_not_ascii_folding() {
    // Incidental, not a designed defence: `(?i)` in the regex crate folds under
    // Unicode, so U+017F LATIN SMALL LETTER LONG S is an `s`. Recorded so that a
    // later switch to `(?i-u:)` for byte matching is seen to lose it.
    let policy = rules(&[], &[]);
    let l = literal();
    let long_s = format!("\u{17f}{}", &l[1..]);
    assert_eq!(breaks(&policy, &long_s), vec!["private-identifiers"]);
    let kelvin = rules(&["fixture-kappa"], &[]);
    assert_eq!(
        breaks(&kelvin, "fixture-\u{212a}appa"),
        vec!["private-identifiers"]
    );
}

#[test]
fn an_allowance_span_does_not_leak_onto_an_abutting_occurrence() {
    // Containment is `s <= start && end <= e`. Both bounds are inclusive by design;
    // what must not happen is an occurrence one byte outside the span being admitted.
    let l = literal();
    let policy = rules(&[], &["citation:"]);
    assert_eq!(
        breaks(&policy, &format!("citation:{l}")),
        vec!["private-identifiers"]
    );
    let policy = rules(&[], &[":citation"]);
    assert_eq!(
        breaks(&policy, &format!("{l}:citation")),
        vec!["private-identifiers"]
    );
    // An allowance that exactly spans the occurrence admits it; a second occurrence
    // one byte past the span end does not ride along.
    let exact = format!("q={}", regex::escape(&l));
    let policy = rules(&[], &[&exact]);
    assert!(breaks(&policy, &format!("q={l}")).is_empty());
    assert_eq!(
        breaks(&policy, &format!("q={l} {l}")),
        vec!["private-identifiers"]
    );
}

#[test]
fn a_bounded_separator_class_catches_the_separators_it_was_bounded_for() {
    let policy = rules(&[r"fixture[\W_]{0,3}(alpha|beta)"], &[]);
    for line in [
        "fixture-alpha",
        "FIXTURE-ALPHA",
        "Fixture_Beta",
        "fixture  alpha",
        "fixtureALPHA",
        // A non-breaking space, a non-breaking hyphen and a zero-width space are all
        // `\W`, so a bounded class covers them.
        "fixture\u{00a0}alpha",
        "fixture\u{2011}alpha",
        "fixture\u{200b}-alpha",
    ] {
        assert_eq!(
            breaks(&policy, line),
            vec!["private-identifiers"],
            "missed: {line}"
        );
    }
    // The bound is the policy author's exposure, not the engine's: four separators
    // walk straight through a `{0,3}` rule.
    assert!(breaks(&policy, "fixture....alpha").is_empty());
}

#[ignore = "DEFECT: line-based scanning. All 30 interior split points of the literal evade; \
            a soft-wrapped paragraph or a hyphenated line break carries the term out"]
#[test]
fn a_literal_split_across_a_line_break_is_still_caught() {
    let policy = rules(&[], &[]);
    let l = literal();
    let matchers = scan::Matchers::build(&policy).unwrap();
    let evading = (1..l.len())
        .filter(|i| {
            matchers
                .text(format!("{}\n{}", &l[..*i], &l[*i..]).as_bytes())
                .is_empty()
        })
        .count();
    assert_eq!(
        evading,
        0,
        "{evading} of {} split points evade",
        l.len() - 1
    );
}

#[ignore = "DEFECT: no normalisation before matching. Percent, HTML-entity, JSON \\u and \
            base64 encodings of the literal all pass; base64 is not covered by Gitleaks \
            either, whose decode depth only applies to its own secret rules"]
#[test]
fn an_encoded_literal_is_still_caught() {
    let policy = rules(&[], &[]);
    let l = literal();
    for line in [
        l.replace('-', "%2D"),
        l.bytes().map(|b| format!("%{b:02X}")).collect(),
        l.replace('-', "&#45;"),
        l.replace('-', "&hyphen;"),
        l.replace('-', "\\u002D"),
        l.replace("-i", "-<wbr>i"),
        "c3ludGhldGljLXJlc3RyaWN0ZWQtaWRlbnRpZmllcg==".into(),
    ] {
        assert_eq!(
            breaks(&policy, &line),
            vec!["private-identifiers"],
            "missed: {line:?}"
        );
    }
}

#[ignore = "DEFECT: no Unicode confusable or invisible-character normalisation. A zero-width \
            space, a soft hyphen, a Cyrillic homoglyph, a combining mark or a fullwidth \
            letter each defeat the literal"]
#[test]
fn a_literal_carrying_invisible_or_confusable_characters_is_still_caught() {
    let policy = rules(&[], &[]);
    let l = literal();
    for line in [
        l.replace('-', "\u{200b}-"),
        l.replace('-', "\u{200c}-"),
        l.replace('-', "\u{00ad}"),
        l.replacen('c', "\u{0441}", 1),
        l.replacen('i', "i\u{0301}", 1),
        format!("\u{ff53}{}", &l[1..]),
    ] {
        assert_eq!(
            breaks(&policy, &line),
            vec!["private-identifiers"],
            "missed: {line:?}"
        );
    }
}

#[ignore = "DEFECT: byte matching assumes UTF-8 or a superset of ASCII. A unit encoded \
            UTF-16 carries the literal past every rule; Latin-1 is fine because the \
            literal itself is ASCII"]
#[test]
fn a_literal_in_a_utf16_unit_is_still_caught() {
    let policy = rules(&[], &[]);
    let utf16: Vec<u8> = literal().bytes().flat_map(|b| [b, 0]).collect();
    assert_eq!(
        breaks_bytes(&policy, &utf16),
        vec!["private-identifiers"],
        "missed: UTF-16LE"
    );
}

#[ignore = "DEFECT: the widened boundary class `[^a-z0-9._\\-\\\\]` still excludes `-` and \
            `_`, so a unified-diff removal line, a tight markdown bullet and `_..._` \
            emphasis each hide a home path. `-` and `_` cannot end a hostname, so \
            admitting them costs no false positive"]
#[test]
fn a_home_path_behind_a_hyphen_or_an_underscore_is_caught() {
    let policy = rules(&[], &[]);
    let h = home();
    for line in [
        format!("_{h}_"),
        format!("-{h}/config"),
        format!("-{h}"),
        format!("ROOT_{h}"),
    ] {
        assert!(
            breaks(&policy, &line).contains(&"personal-paths"),
            "missed: {line}"
        );
    }
}

#[ignore = "DEFECT: the boundary class is a Unicode class, so it cannot match a byte that \
            is not valid UTF-8. One Latin-1 byte before the path hides it. Fix: wrap the \
            class in `(?-u:)` so it is a byte class"]
#[test]
fn a_home_path_behind_an_invalid_utf8_byte_is_caught() {
    let policy = rules(&[], &[]);
    for prefix in [0xffu8, 0x80, 0xe9] {
        let mut line = vec![prefix];
        line.extend_from_slice(home().as_bytes());
        assert!(
            breaks_bytes(&policy, &line).contains(&"personal-paths"),
            "missed: byte {prefix:#04x} before a home path"
        );
    }
}

#[test]
fn a_rest_route_is_not_a_personal_path() {
    let policy = rules(&[], &[]);
    // Built rather than written, for the same reason `home()` is: this file must not
    // carry a string that reads as a machine-local path.
    let users = ["", "users", ""].join("/");
    let home = ["", "home", ""].join("/");
    for line in [
        format!("`{users}me` returns the caller"),
        format!("GET {users}me"),
        format!("  \"{users}profile\": {{ \"get\": {{}} }}"),
        format!("| `{users}me` | the caller |"),
        format!("[Home]({home}index.html)"),
        format!("<a href=\"{users}settings\">settings</a>"),
        format!("router.get('{users}list', handler)"),
        format!("- {users}search is paginated"),
    ] {
        assert!(
            !breaks(&policy, &line).contains(&"personal-paths"),
            "false positive: {line}"
        );
    }
}

#[test]
fn an_allowance_admits_only_its_named_group_never_the_text_around_it() {
    let l = literal();
    // The allowance names the citation; the label beside it is not admitted.
    for (allow, line) in [
        (
            r"\[[^\]]+\]\((?P<admit>[^)]+)\)",
            format!("[{l}](https://example.invalid/x)"),
        ),
        (
            r"(?P<admit>https://example\.invalid/docs)#\S*",
            format!("see https://example.invalid/docs#{l}"),
        ),
        (
            r"(?P<admit>https://example\.invalid/s)\?\S*",
            format!("https://example.invalid/s?q={l}"),
        ),
        (
            r"(?P<admit>https://github\.com/[a-z0-9._]+/[a-z0-9._]+)",
            format!("https://github.com/example/repo-{l}"),
        ),
    ] {
        let policy = rules(&[], &[allow]);
        assert_eq!(
            breaks(&policy, &line),
            vec!["private-identifiers"],
            "allowance {allow:?} swallowed prose in {line:?}"
        );
    }
    // And the citation itself still passes.
    let policy = rules(&[], &[r"\[[^\]]+\]\((?P<admit>[^)]+)\)"]);
    assert!(breaks(&policy, &format!("[upstream](https://example.invalid/{l})")).is_empty());
}

#[ignore = "DEFECT: an allowance is not scoped to a rule. A citation allowance written for \
            `private-identifiers` silently disables `personal-paths` inside its span, and \
            a `file://` allowance is exactly the shape that covers a home path"]
#[test]
fn an_allowance_does_not_admit_a_rule_it_was_not_written_for() {
    let policy = rules(&[], &[r"file://\S+"]);
    assert!(
        breaks(&policy, &format!("file://{}/x", home())).contains(&"personal-paths"),
        "a citation allowance admitted a home path"
    );
}

#[test]
fn an_allow_pattern_that_admits_everything_is_refused() {
    for allow in [r".*", r"(?s).*", r"[\s\S]*", r"\S*", r"^", r".+"] {
        let policy = rules(&[], &[allow]);
        assert!(
            policy.validate().is_err(),
            "accepted allow pattern {allow:?}"
        );
        assert!(
            scan::Matchers::build(&policy).is_err(),
            "built matchers for allow pattern {allow:?}"
        );
    }
}

#[test]
fn an_allowance_must_name_what_it_admits() {
    let mut policy = rules(&[], &[]);
    policy.allow_patterns = vec![r"https://example\.invalid/\S+".into()];
    assert!(policy.validate().is_err(), "accepted an unnamed allowance");
    assert!(scan::Matchers::build(&policy).is_err());
}

#[test]
fn a_forbidden_pattern_that_matches_everything_is_refused() {
    for pattern in [r".*", r"^", r"\b", r"(?s).*", r"\S*"] {
        let policy = rules(&[pattern], &[]);
        assert!(
            policy.validate().is_err(),
            "accepted forbidden pattern {pattern:?}"
        );
        assert!(
            scan::Matchers::build(&policy).is_err(),
            "built matchers for forbidden pattern {pattern:?}"
        );
    }
}

#[test]
fn span_containment_is_not_quadratic_in_line_length() {
    use std::time::Instant;
    let policy = rules(&[r"invalid"], &[r#"https?://[^\s"']+"#]);
    let matchers = scan::Matchers::build(&policy).unwrap();
    // A ratio, not a wall clock: a debug build is an order of magnitude slower than
    // a release one and CI is slower than this machine, but quadratic is quadratic.
    let measure = |repeats: usize| {
        let line = "https://example.invalid/a ".repeat(repeats);
        let started = Instant::now();
        let _ = matchers.line(line.as_bytes());
        started.elapsed()
    };
    let _ = measure(2_000);
    let small = measure(10_000);
    let large = measure(40_000);
    // Four times the input. Linear is 4x, quadratic is 16x.
    assert!(
        large.as_nanos() < small.as_nanos().saturating_mul(8).max(8_000_000),
        "4x the line took {large:.1?} against {small:.1?}"
    );
}

#[test]
fn a_unc_user_profile_path_is_a_personal_path() {
    let policy = rules(&[], &[]);
    assert!(
        breaks(&policy, "\\\\fileserver\\Users\\fixture.person\\notes").contains(&"personal-paths"),
        "missed a UNC user profile path"
    );
}

#[test]
fn a_line_the_previous_version_already_carried_is_not_introduced_by_this_change() {
    let f = Fixture::new();
    let l = literal();
    let carried = format!("upstream is {l}\n");
    let mut unit = unit(format!("{carried}a new and harmless line\n"));
    // Without a predecessor the whole file is answerable.
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        std::slice::from_ref(&unit),
        &mut CountScanner::default(),
    )
    .unwrap();
    assert_eq!(report.results["private-identifiers"].findings, 1);
    // With one that already carried the line, editing the file elsewhere is clean.
    unit.inherited = Some(carried.clone().into_bytes());
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        std::slice::from_ref(&unit),
        &mut CountScanner::default(),
    )
    .unwrap();
    assert_eq!(report.results["private-identifiers"].findings, 0);
    // A new occurrence in the same file is still refused.
    let added = unit_with(format!("{carried}and now {l} again\n"), Some(carried));
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        std::slice::from_ref(&added),
        &mut CountScanner::default(),
    )
    .unwrap();
    assert_eq!(report.results["private-identifiers"].findings, 1);
}

#[test]
fn a_binary_unit_is_left_to_the_secret_scanner() {
    let f = Fixture::new();
    let l = literal();
    let mut bytes = vec![0u8, 1, 2, 3];
    bytes.extend_from_slice(l.as_bytes());
    let report = scan::run(
        &f.policy,
        REPOSITORY,
        &[unit(&bytes)],
        &mut CountScanner::default(),
    )
    .unwrap();
    assert_eq!(report.results["private-identifiers"].findings, 0);
}

#[test]
fn an_exception_may_cover_a_generated_tree_without_a_line_or_a_digest() {
    let mut f = Fixture::new();
    let l = literal();
    let unit = Unit {
        location: "file:generated/a/manifest.json".into(),
        bytes: format!("first\n{l}\n").into_bytes(),
        workflow: false,
        inherited: None,
    };
    let count = |f: &Fixture, unit: &Unit| {
        scan::run(
            &f.policy,
            REPOSITORY,
            std::slice::from_ref(unit),
            &mut CountScanner::default(),
        )
        .unwrap()
        .results["private-identifiers"]
            .findings
    };
    assert_eq!(count(&f, &unit), 1);
    f.policy.exceptions.push(Exception {
        repository: REPOSITORY.into(),
        rule: "private-identifiers".into(),
        location: "file:generated/*".into(),
        content_sha256: String::new(),
        line: 0,
    });
    f.policy.validate().unwrap();
    assert_eq!(count(&f, &unit), 0);
    // The prefix binds: a sibling tree is not covered.
    let other = Unit {
        location: "file:src/a/manifest.json".into(),
        ..unit
    };
    assert_eq!(count(&f, &other), 1);
    // And a bare `*` is refused rather than admitting the repository.
    f.policy.exceptions[0].location = "*".into();
    assert!(f.policy.validate().is_err());
}
