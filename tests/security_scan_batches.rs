//! Security conformance for `story:scan-bounded-batches`. A receipt is signed only after every
//! unit of every commit and tag in range was read as bound and inspected by both the private
//! rules and the secret scanner; a failure in any batch refuses the whole candidate and signs
//! nothing; `objects_digest` is the digest of exactly the bytes the batches scanned; and the
//! process holds about one batch of candidate bytes, whatever the candidate's size.
use b10x_gates::{
    BOT_EMAIL, BOT_NAME, digest, evidence,
    git::{Git, Unit},
    policy::{Policy, Repository, Signer},
    scan::{self, Gitleaks, Report, SecretFinding, SecretScanner},
};
use ed25519_dalek::SigningKey;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

const REPOSITORY: &str = "example/repository";

/// The lowered batch limit, through the library constructor only.
const LIMIT: usize = 64 * 1024;

/// The per-blob limit, which no batch limit changes.
const MAX_BLOB: usize = 128 * 1024 * 1024;

/// A line the fake secret scanner reports wherever it occurs.
const SECRET_MARK: &str = "fixture-secret-marker";

const KEY: [u8; 32] = [29; 32];

const WORKFLOW: &[u8] =
    b"permissions: {}\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n";

/// The memory case: a batch limit of 1 MiB over candidates of 40 files of 640 KiB each.
const MEMORY_LIMIT: usize = 1024 * 1024;
const MEMORY_FILE: usize = 640 * 1024;
const MEMORY_FILES: usize = 40;
const MEMORY_CHILD: &str = "memory_child_entry_point";

/// One unit as a scanner was handed it: location, SHA-256 of its bytes, workflow flag.
type Seen = (String, String, bool);

/// Records each batch, reports a secret on every line containing `SECRET_MARK`, and fails
/// its `fail_at`-th invocation (counted from 1) when that is set.
#[derive(Default)]
struct Marks {
    seen: Vec<Vec<Seen>>,
    fail_at: Option<usize>,
}

impl Marks {
    fn failing(at: usize) -> Self {
        Self {
            seen: Vec::new(),
            fail_at: Some(at),
        }
    }

    /// The batch a location was scanned in, and its index inside that batch.
    fn place(&self, location: &str) -> Option<(usize, usize)> {
        self.seen.iter().enumerate().find_map(|(batch, units)| {
            units
                .iter()
                .position(|u| u.0 == location)
                .map(|i| (batch, i))
        })
    }
}

impl SecretScanner for Marks {
    fn scan(&mut self, units: &[Unit]) -> anyhow::Result<Vec<SecretFinding>> {
        self.seen.push(
            units
                .iter()
                .map(|u| (u.location.clone(), digest(&u.bytes), u.workflow))
                .collect(),
        );
        if self.fail_at == Some(self.seen.len()) {
            anyhow::bail!("injected scanner failure in batch {}", self.seen.len());
        }
        let mut found = Vec::new();
        for (unit, u) in units.iter().enumerate() {
            for (line, bytes) in u.bytes.split(|b| *b == b'\n').enumerate() {
                if bytes
                    .windows(SECRET_MARK.len())
                    .any(|w| w == SECRET_MARK.as_bytes())
                {
                    found.push(SecretFinding {
                        unit,
                        line: line + 1,
                    });
                }
            }
        }
        Ok(found)
    }
}

/// Keeps nothing and reports nothing, so a memory measurement sees only what Gates holds.
struct Quiet;

impl SecretScanner for Quiet {
    fn scan(&mut self, _: &[Unit]) -> anyhow::Result<Vec<SecretFinding>> {
        Ok(Vec::new())
    }
}

fn policy(baseline: String) -> Policy {
    let key = SigningKey::from_bytes(&KEY);
    Policy {
        version: 1,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::from([(
            REPOSITORY.into(),
            Repository {
                id: "123".into(),
                baseline,
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
    }
}

struct Fixture {
    dir: TempDir,
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
        Self {
            dir,
            policy: policy(baseline),
            key: SigningKey::from_bytes(&KEY),
        }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn denied(&self) -> String {
        self.policy.forbidden_literals[0].clone()
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        let file = self.root().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        git(self.root(), &["add", "-A"]);
        git(self.root(), &["commit", "-qm", message]);
        git(self.root(), &["rev-parse", "HEAD"])
    }

    /// `count` commits, each adding `{prefix}-{i}.txt` of `size` clean bytes.
    fn files(&self, prefix: &str, count: usize, size: usize) -> Vec<String> {
        (0..count)
            .map(|i| {
                self.write(
                    &format!("{prefix}-{i:02}.txt"),
                    &filler(&format!("{prefix} {i}"), size),
                );
                self.commit(&format!("add {prefix} {i}"))
            })
            .collect()
    }

    fn limited(&self) -> Git {
        Git::with_batch_limit(self.root(), LIMIT).unwrap()
    }

    fn loose(&self, oid: &str) -> PathBuf {
        self.root()
            .join(".git/objects")
            .join(&oid[..2])
            .join(&oid[2..])
    }
}

/// Git with the bot identity and fixed dates, so a fixture's ids are reproducible.
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
        .env("GIT_AUTHOR_DATE", "1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "1700000000 +0000")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Git fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

/// `size` bytes of numbered lines that break no rule.
fn filler(seed: &str, size: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(size + 64);
    let mut line = 0;
    while bytes.len() < size {
        bytes.extend_from_slice(format!("safe filler {seed} line {line:06}\n").as_bytes());
        line += 1;
    }
    bytes.truncate(size);
    bytes
}

fn findings(report: &Report) -> Vec<(String, String, usize)> {
    report
        .findings
        .iter()
        .map(|v| (v.rule.clone(), v.location.clone(), v.line))
        .collect()
}

/// Every unit kind carries a forbidden literal and a secret: filenames, file bytes, commit
/// messages, the tag ref and two nested annotated tags, cut into several batches. Each unit
/// must be reported by the private rules and by the secret scanner.
#[test]
fn every_unit_of_every_commit_and_tag_meets_both_rule_sets_across_batches() {
    let f = Fixture::new();
    let denied = f.denied();
    let mut head = String::new();
    for i in 0..6 {
        let mut bytes = filler(&format!("unit {i}"), 24 * 1024);
        bytes.extend_from_slice(format!("{denied} {SECRET_MARK}\n").as_bytes());
        f.write(&format!("data/{denied}-{SECRET_MARK}-{i}.txt"), &bytes);
        head = f.commit(&format!("commit {i} {denied} {SECRET_MARK}"));
    }
    let inner = format!("{denied}-{SECRET_MARK}-inner");
    let outer = format!("{denied}-{SECRET_MARK}-outer");
    git(
        f.root(),
        &[
            "tag",
            "-a",
            &inner,
            "-m",
            &format!("inner {denied} {SECRET_MARK}"),
        ],
    );
    git(
        f.root(),
        &[
            "tag",
            "-a",
            &outer,
            &format!("refs/tags/{inner}"),
            "-m",
            &format!("outer {denied} {SECRET_MARK}"),
        ],
    );
    let candidate = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &[outer])
        .unwrap();
    for kind in ["filename:", "file:", "commit:", "tag-ref", "tag:"] {
        assert!(
            candidate.units.iter().any(|u| u.location.starts_with(kind)),
            "no {kind} unit in the fixture"
        );
    }
    let mut scanner = Marks::default();
    let report = scan::run_batches(&f.policy, REPOSITORY, &candidate.units, &mut scanner).unwrap();
    assert!(scanner.seen.len() > 2, "{} batches", scanner.seen.len());
    let found = findings(&report);
    for unit in candidate.units.iter() {
        for rule in ["private-identifiers", "secrets"] {
            assert!(
                found
                    .iter()
                    .any(|(r, l, _)| r == rule && *l == unit.location),
                "{rule} never reported {} (batch {:?})",
                unit.location,
                scanner.place(&unit.location)
            );
        }
    }
    let refused = evidence::check(&f.policy, &candidate, &f.key, &mut Marks::default())
        .expect_err("a candidate with findings in every unit was signed")
        .to_string();
    assert!(refused.contains("common checks failed"), "{refused}");
}

/// The secret scanner fails in batch `k`, for every `k` of a full scan and of a scan that
/// reuses an ancestor receipt: every path refuses and none returns a receipt.
#[test]
fn a_scanner_failure_in_any_batch_refuses_the_whole_candidate_and_signs_nothing() {
    let f = Fixture::new();
    let commits = f.files("data/part", 6, 24 * 1024);
    let git = f.limited();
    let ancestor = git
        .candidate(&f.policy, REPOSITORY, &commits[1], &[])
        .unwrap();
    let retained = evidence::check(&f.policy, &ancestor, &f.key, &mut Marks::default()).unwrap();
    let candidate = git
        .candidate(&f.policy, REPOSITORY, &commits[5], &[])
        .unwrap();
    let mut whole = Marks::default();
    evidence::check(&f.policy, &candidate, &f.key, &mut whole).unwrap();
    let mut part = Marks::default();
    let checked = evidence::check_reusing(
        &f.policy,
        &git,
        &candidate,
        std::slice::from_ref(&retained),
        &f.key,
        &mut part,
    )
    .unwrap();
    assert_eq!(checked.reused.as_deref(), Some(commits[1].as_str()));
    assert!(
        whole.seen.len() >= 3 && part.seen.len() >= 2,
        "{} and {} batches",
        whole.seen.len(),
        part.seen.len()
    );
    for at in 1..=whole.seen.len() {
        let refused = evidence::check(&f.policy, &candidate, &f.key, &mut Marks::failing(at))
            .err()
            .unwrap_or_else(|| panic!("signed although batch {at} of the scan failed"));
        assert!(
            format!("{refused:#}").contains("injected scanner failure"),
            "{refused:#}"
        );
        assert!(
            evidence::reuse_or_scan(&f.policy, &candidate, None, &mut Marks::failing(at)).is_err(),
            "ci passed although batch {at} of its scan failed"
        );
    }
    for at in 1..=part.seen.len() {
        assert!(
            evidence::check_reusing(
                &f.policy,
                &git,
                &candidate,
                std::slice::from_ref(&retained),
                &f.key,
                &mut Marks::failing(at),
            )
            .is_err(),
            "signed after reuse although batch {at} of the remaining scan failed"
        );
    }
}

/// After the build, the last file blob, the head commit or the tag object becomes unreadable.
/// The batches before it are scanned, and the candidate is still refused and not signed.
#[test]
fn a_read_failure_in_a_later_batch_refuses_after_earlier_batches_were_scanned() {
    let f = Fixture::new();
    let commits = f.files("data/part", 6, 24 * 1024);
    let head = commits[5].clone();
    git(f.root(), &["tag", "-a", "release", "-m", "release notes"]);
    let tag = git(f.root(), &["rev-parse", "refs/tags/release"]);
    let blob = git(
        f.root(),
        &["rev-parse", &format!("{head}:data/part-05.txt")],
    );
    let candidate = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &["release".to_owned()])
        .unwrap();
    let aside = f.root().join(".git").join("aside");
    for (what, oid) in [("file blob", &blob), ("head commit", &head), ("tag", &tag)] {
        let loose = f.loose(oid);
        fs::rename(&loose, &aside).unwrap();
        let mut scanner = Marks::default();
        let refused = evidence::check(&f.policy, &candidate, &f.key, &mut scanner);
        fs::rename(&aside, &loose).unwrap();
        assert!(
            refused.is_err(),
            "{what}: signed over an object that could not be read"
        );
        assert!(
            !scanner.seen.is_empty(),
            "{what}: the read failed in the first batch, not a later one"
        );
    }
    evidence::check(&f.policy, &candidate, &f.key, &mut Marks::default()).unwrap();
}

/// The manifest rebuilt from what the scanner was handed, batch after batch, digests to the
/// `objects_digest` the candidate and its receipt carry: nothing bound went unscanned and
/// nothing scanned went unbound.
#[test]
fn objects_digest_is_the_digest_of_exactly_the_bytes_the_batches_scanned() {
    let f = Fixture::new();
    f.write(".github/workflows/check.yml", WORKFLOW);
    f.commit("workflow");
    f.files("data/part", 5, 24 * 1024);
    f.write("data/part-00.txt", &filler("edited", 20 * 1024));
    let head = f.commit("edit");
    git(f.root(), &["tag", "-a", "inner", "-m", "inner notes"]);
    git(
        f.root(),
        &["tag", "-a", "outer", "refs/tags/inner", "-m", "outer notes"],
    );
    let candidate = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &["outer".to_owned()])
        .unwrap();
    let mut scanner = Marks::default();
    let receipt = evidence::check(&f.policy, &candidate, &f.key, &mut scanner).unwrap();
    assert!(scanner.seen.len() > 2, "{} batches", scanner.seen.len());
    let scanned: Vec<Seen> = scanner.seen.concat();
    assert!(scanned.iter().any(|u| u.2), "no workflow unit was scanned");
    assert_eq!(
        digest(&serde_json::to_vec(&scanned).unwrap()),
        candidate.binding.objects_digest
    );
    assert_eq!(
        receipt.payload.binding.objects_digest,
        candidate.binding.objects_digest
    );
}

/// The pinned Gitleaks over a candidate cut into batches: candidate scanner configuration,
/// an ignore file and an inline allow comment change nothing, and the credential is reported
/// at its own location although it is neither in the first batch nor first in its batch.
#[test]
fn pinned_gitleaks_reads_each_batch_as_data_and_places_a_credential_in_a_later_batch() {
    let binary = std::env::var_os("B10X_GATES_GITLEAKS")
        .expect("set B10X_GATES_GITLEAKS to the pinned binary; this scanner test must not skip");
    let f = Fixture::new();
    f.files("data/part", 6, 24 * 1024);
    let token = format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    f.write(".gitleaks.toml", b"[allowlist]\nregexes = ['.*']\n");
    f.write(".gitleaksignore", b"z/credential.txt:github-pat:1\n");
    f.write(
        "z/credential.txt",
        format!("token = '{token}' # gitleaks:allow\n").as_bytes(),
    );
    f.write("z/decoy.txt", b"nothing to report here\n");
    let head = f.commit("scanner configuration, a credential and a decoy");
    let candidate = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let mut cut = Marks::default();
    scan::run_batches(&f.policy, REPOSITORY, &candidate.units, &mut cut).unwrap();
    let (batch, index) = cut.place("file:z/credential.txt").unwrap();
    assert!(batch > 0 && index > 0, "credential at {batch}/{index}");
    let report = scan::run_batches(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut Gitleaks {
            binary: binary.into(),
        },
    )
    .unwrap();
    let secrets: BTreeSet<(String, usize)> = report
        .findings
        .iter()
        .filter(|v| v.rule == "secrets")
        .map(|v| (v.location.clone(), v.line))
        .collect();
    assert_eq!(
        secrets,
        BTreeSet::from([("file:z/credential.txt".to_owned(), 1)])
    );
    assert!(
        !serde_json::to_string(&report.findings)
            .unwrap()
            .contains(&token)
    );
}

/// A predecessor that is absent or over the per-blob limit cannot be read, so nothing is
/// inherited from it and the whole edited file is answerable: a forbidden line the old
/// version also carried is reported, which a readable predecessor would have excused.
#[test]
fn a_predecessor_that_cannot_be_read_inherits_nothing() {
    for case in ["readable", "absent", "oversized"] {
        let mut f = Fixture::new();
        let denied = f.denied();
        let mut old = format!("{denied}\n").into_bytes();
        if case == "oversized" {
            old.resize(MAX_BLOB + 1, b'x');
        }
        f.write("notes.md", &old);
        let baseline = f.commit("notes at the baseline");
        f.policy.repositories.get_mut(REPOSITORY).unwrap().baseline = baseline.clone();
        let predecessor = git(f.root(), &["rev-parse", &format!("{baseline}:notes.md")]);
        f.write("notes.md", format!("{denied}\nnew safe line\n").as_bytes());
        let head = f.commit("edit notes");
        if case == "absent" {
            fs::remove_file(f.loose(&predecessor)).unwrap();
        }
        let candidate = f
            .limited()
            .candidate(&f.policy, REPOSITORY, &head, &[])
            .unwrap();
        let report = scan::run_batches(
            &f.policy,
            REPOSITORY,
            &candidate.units,
            &mut Marks::default(),
        )
        .unwrap();
        let reported = findings(&report).contains(&(
            "private-identifiers".to_owned(),
            "file:notes.md".to_owned(),
            1,
        ));
        assert_eq!(
            reported,
            case != "readable",
            "{case}: {:?}",
            findings(&report)
        );
        assert_eq!(
            evidence::check(&f.policy, &candidate, &f.key, &mut Marks::default()).is_ok(),
            case == "readable",
            "{case}"
        );
    }
}

/// The peak resident memory one operation adds, measured in a child process of this test
/// binary so no other test shares the address space. The control reads every unit at once,
/// so the measurement is shown to see a path that holds the whole candidate.
#[test]
fn process_memory_stays_near_one_batch_whatever_the_candidate_size() {
    let f = Fixture::new();
    let commits = f.files("data/big", MEMORY_FILES, MEMORY_FILE);
    for i in 0..MEMORY_FILES {
        f.write(
            &format!("staged/big-{i:02}.txt"),
            &filler(&format!("staged {i}"), MEMORY_FILE),
        );
    }
    git(f.root(), &["add", "-A"]);
    let total = MEMORY_FILES * MEMORY_FILE;
    let growth = |operation: &str| -> usize {
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                MEMORY_CHILD,
                "--exact",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("B10X_SEC_BATCH_REPO", f.root())
            .env("B10X_SEC_BATCH_OPERATION", operation)
            .env("B10X_SEC_BATCH_FIRST", &commits[0])
            .env("B10X_SEC_BATCH_ANCESTOR", &commits[MEMORY_FILES / 2])
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{operation}: child failed\n{stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        stdout
            .lines()
            .find_map(|line| line.split("GROWTH_BYTES=").nth(1))
            .unwrap_or_else(|| panic!("{operation}: no measurement\n{stdout}"))
            .trim()
            .parse()
            .unwrap()
    };
    let control = growth("control");
    assert!(
        control > total * 3 / 4,
        "the measurement does not see a path holding every unit: {control} of {total} bytes"
    );
    for operation in [
        "build",
        "scan",
        "check",
        "reuse",
        "ci",
        "staged",
        "historical",
    ] {
        let held = growth(operation);
        println!("{operation}: {held} of {total} bytes (control {control})");
        assert!(
            held < total / 4,
            "{operation} added {held} bytes of resident memory for a {total}-byte candidate \
             cut into {MEMORY_LIMIT}-byte batches"
        );
    }
}

/// Peak resident bytes of this process since the last reset.
fn peak() -> usize {
    let status = fs::read_to_string("/proc/self/status").unwrap();
    let kib: usize = status
        .lines()
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|v| v.trim().strip_suffix("kB"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    kib * 1024
}

/// Reset the peak to the current resident size and return it.
fn reset_peak() -> usize {
    fs::write("/proc/self/clear_refs", "5").unwrap();
    peak()
}

#[test]
#[ignore = "child process entry point: run by process_memory_stays_near_one_batch_whatever_the_candidate_size"]
fn memory_child_entry_point() {
    let var = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} unset"));
    let root = PathBuf::from(var("B10X_SEC_BATCH_REPO"));
    let operation = var("B10X_SEC_BATCH_OPERATION");
    let (first, ancestor) = (var("B10X_SEC_BATCH_FIRST"), var("B10X_SEC_BATCH_ANCESTOR"));
    let baseline = git(&root, &["rev-list", "--max-parents=0", "HEAD"]);
    let head = git(&root, &["rev-parse", "HEAD"]);
    let policy = policy(baseline);
    let key = SigningKey::from_bytes(&KEY);
    let git = Git::with_batch_limit(&root, MEMORY_LIMIT).unwrap();
    // Touch every code path once over one commit, so first-use code pages are not counted.
    let small = git.candidate(&policy, REPOSITORY, &first, &[]).unwrap();
    evidence::check(&policy, &small, &key, &mut Quiet).unwrap();
    scan::run_batches(
        &policy,
        REPOSITORY,
        &git.historical(&first).unwrap(),
        &mut Quiet,
    )
    .unwrap();
    drop(small);
    // The build is measured from nothing; every other operation gets its candidate first.
    let candidate =
        (operation != "build").then(|| git.candidate(&policy, REPOSITORY, &head, &[]).unwrap());
    let retained: Vec<evidence::Receipt> = if operation == "reuse" {
        let proved = git.candidate(&policy, REPOSITORY, &ancestor, &[]).unwrap();
        vec![evidence::check(&policy, &proved, &key, &mut Quiet).unwrap()]
    } else {
        Vec::new()
    };
    let before = reset_peak();
    match (operation.as_str(), candidate.as_ref()) {
        ("build", None) => {
            let built = git.candidate(&policy, REPOSITORY, &head, &[]).unwrap();
            assert_eq!(built.binding.commits.len(), MEMORY_FILES);
        }
        ("scan", Some(c)) => {
            scan::run_batches(&policy, REPOSITORY, &c.units, &mut Quiet)
                .unwrap()
                .require_success()
                .unwrap();
        }
        ("check", Some(c)) => {
            evidence::check(&policy, c, &key, &mut Quiet).unwrap();
        }
        ("reuse", Some(c)) => {
            let checked =
                evidence::check_reusing(&policy, &git, c, &retained, &key, &mut Quiet).unwrap();
            assert_eq!(checked.reused.as_deref(), Some(ancestor.as_str()));
        }
        ("ci", Some(c)) => {
            assert!(!evidence::reuse_or_scan(&policy, c, None, &mut Quiet).unwrap());
        }
        ("staged", Some(_)) => {
            let units = git.staged().unwrap();
            assert_eq!(units.len(), 2 * MEMORY_FILES);
            scan::run_batches(&policy, REPOSITORY, &units, &mut Quiet).unwrap();
        }
        ("historical", Some(_)) => {
            let units = git.historical(&head).unwrap();
            scan::run_batches(&policy, REPOSITORY, &units, &mut Quiet).unwrap();
        }
        ("control", Some(c)) => {
            let all = c.units.read_all().unwrap();
            assert_eq!(all.len(), c.units.len());
        }
        (other, _) => panic!("unknown operation {other}"),
    }
    println!("GROWTH_BYTES={}", peak().saturating_sub(before));
}
