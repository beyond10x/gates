//! A candidate is scanned in batches of bounded size, so its total size is no limit.
use b10x_gates::{
    BOT_EMAIL, BOT_NAME, digest, evidence,
    git::{Git, Unit, UnitRef},
    policy::{Policy, Repository, Signer},
    scan::{self, SecretFinding, SecretScanner},
};
use ed25519_dalek::SigningKey;
use std::{collections::BTreeMap, fs, path::Path, process::Command};
use tempfile::TempDir;

const REPOSITORY: &str = "example/repository";

/// The batch limit these tests lower the default 256 MiB to, through the library only.
const LIMIT: usize = 64 * 1024;

/// The per-blob limit, which no batch limit changes.
const MAX_BLOB: usize = 128 * 1024 * 1024;

/// A line the fake secret scanner reports, as Gitleaks reports a credential.
const SECRET_MARK: &str = "fixture-secret-marker";

/// What `b10x-gates` 0.1.25, which still refused a candidate by its total size, bound and
/// signed for the commits of `small()`.
const SMALL_OBJECTS_DIGEST: &str =
    "35f4a9656d0e81f793a20bb389f5a07cfa2b9f0b56f268de36b954fd53c21e77";
const SMALL_RESULTS: &str = concat!(
    r#"{"commit-authorship":{"inspected":2,"findings":0},"#,
    r#""personal-paths":{"inspected":12,"findings":0},"#,
    r#""private-identifiers":{"inspected":12,"findings":0},"#,
    r#""secrets":{"inspected":12,"findings":0},"#,
    r#""workflow-permissions":{"inspected":1,"findings":0},"#,
    r#""workflow-pins":{"inspected":1,"findings":0}}"#,
);

/// A secret scanner that records every batch it is handed (per unit, its location and its
/// bytes plus its predecessor's) and reports a secret on every line carrying `SECRET_MARK`.
#[derive(Default)]
struct Batches {
    seen: Vec<Vec<(String, usize)>>,
}
impl SecretScanner for Batches {
    fn scan(&mut self, units: &[Unit]) -> anyhow::Result<Vec<SecretFinding>> {
        self.seen.push(
            units
                .iter()
                .map(|u| {
                    (
                        u.location.clone(),
                        u.bytes.len() + u.inherited.as_ref().map_or(0, Vec::len),
                    )
                })
                .collect(),
        );
        let mut found = Vec::new();
        for (unit, u) in units.iter().enumerate() {
            for (line, bytes) in u.bytes.split(|b| *b == b'\n').enumerate() {
                if bytes == SECRET_MARK.as_bytes() {
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

impl Batches {
    fn sizes(&self) -> Vec<usize> {
        self.seen
            .iter()
            .map(|batch| batch.iter().map(|(_, size)| size).sum())
            .collect()
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
        };
        Self { dir, policy, key }
    }

    fn write(&self, path: &str, bytes: &[u8]) {
        let file = self.dir.path().join(path);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(file, bytes).unwrap();
    }

    fn commit(&self, message: &str) -> String {
        git(self.dir.path(), &["add", "-A"]);
        git(self.dir.path(), &["commit", "-qm", message]);
        git(self.dir.path(), &["rev-parse", "HEAD"])
    }

    /// `count` files of `size` clean bytes each under `data/`, all added in one commit and
    /// all rewritten in a second, so each rewritten file carries a predecessor as large.
    fn parts(&self, count: usize, size: usize) -> String {
        let mut head = String::new();
        for round in ["first", "second"] {
            for i in 0..count {
                self.write(
                    &format!("data/part-{i:02}.txt"),
                    &filler(&format!("{round} {i}"), size),
                );
            }
            head = self.commit(&format!("{round} parts"));
        }
        head
    }

    fn limited(&self) -> Git {
        Git::with_batch_limit(self.dir.path(), LIMIT).unwrap()
    }
}

/// Git with the bot identity and fixed dates, so a fixture's commit ids are reproducible.
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

/// A few small files over two commits: an edited file with a predecessor, a new file and a
/// workflow.
fn small() -> (Fixture, String) {
    let f = Fixture::new();
    f.write("readme", b"initial safe bytes\nsecond safe line\n");
    f.write("docs/guide.md", b"# Guide\n\nSafe prose.\n");
    f.write(
        ".github/workflows/check.yml",
        b"permissions: {}\njobs:\n  check:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n",
    );
    f.commit("add guide and workflow");
    f.write("docs/guide.md", b"# Guide\n\nSafe prose, edited.\n");
    f.write("src/lib.rs", b"pub fn safe() {}\n");
    let head = f.commit("edit guide");
    (f, head)
}

#[test]
fn candidate_over_the_old_cap_is_admitted() {
    let f = Fixture::new();
    let head = f.parts(10, 24 * 1024);
    let git = f.limited();
    let candidate = git.candidate(&f.policy, REPOSITORY, &head, &[]).unwrap();
    // The old cap was two batches' worth (512 MiB against 256 MiB); this is over three.
    let total: usize = candidate.units.iter().map(UnitRef::weight).sum();
    assert!(total > 3 * LIMIT, "candidate of {total} bytes");
    let mut scanner = Batches::default();
    let receipt = evidence::check(&f.policy, &candidate, &f.key, &mut scanner).unwrap();
    assert!(scanner.seen.len() > 3, "{} batches", scanner.seen.len());
    evidence::verify(&f.policy, &candidate, &receipt).unwrap();
    // The binding does not depend on the batch limit.
    let unlimited = Git::new(f.dir.path())
        .unwrap()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    evidence::verify(&f.policy, &unlimited, &receipt).unwrap();
    // The baseline audit reads a whole tree and is cut the same way.
    let tree = git.historical(&head).unwrap();
    let mut scanner = Batches::default();
    let report = scan::run_batches(&f.policy, REPOSITORY, &tree, &mut scanner).unwrap();
    assert!(report.findings.is_empty());
    assert!(scanner.seen.len() > 3, "{} batches", scanner.seen.len());
}

#[test]
fn finding_in_the_last_batch_is_refused() {
    let f = Fixture::new();
    f.parts(6, 24 * 1024);
    let denied = &f.policy.forbidden_literals[0];
    f.write(
        "notes/last.md",
        format!("safe line\n{denied}\n{SECRET_MARK}\n").as_bytes(),
    );
    let head = f.commit("add notes");
    let candidate = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let mut scanner = Batches::default();
    let report = scan::run_batches(&f.policy, REPOSITORY, &candidate.units, &mut scanner).unwrap();
    let (last, earlier) = scanner.seen.split_last().unwrap();
    assert!(!earlier.is_empty(), "the candidate fits one batch");
    let planted = "file:notes/last.md";
    assert!(last.iter().any(|(location, _)| location == planted));
    assert!(
        earlier
            .iter()
            .flatten()
            .all(|(location, _)| location != planted)
    );
    let found: Vec<_> = report
        .findings
        .iter()
        .map(|v| (v.rule.as_str(), v.location.as_str(), v.line))
        .collect();
    assert!(
        found.contains(&("private-identifiers", planted, 2)),
        "{found:?}"
    );
    assert!(found.contains(&("secrets", planted, 3)), "{found:?}");
    assert_eq!(report.results["private-identifiers"].findings, 1);
    assert_eq!(report.results["secrets"].findings, 1);
    let refused = evidence::check(&f.policy, &candidate, &f.key, &mut Batches::default())
        .expect_err("a finding in the last batch must refuse the receipt")
        .to_string();
    assert!(refused.contains("common checks failed"), "{refused}");
}

#[test]
fn no_batch_exceeds_the_limit() {
    let f = Fixture::new();
    let head = f.parts(8, 20 * 1024);
    let git = f.limited();
    let candidate = git.candidate(&f.policy, REPOSITORY, &head, &[]).unwrap();
    let mut scanner = Batches::default();
    evidence::check(&f.policy, &candidate, &f.key, &mut scanner).unwrap();
    assert!(scanner.seen.len() > 1, "the candidate fits one batch");
    for size in scanner.sizes() {
        assert!(size <= LIMIT, "a batch of {size} bytes, over {LIMIT}");
    }
    // Every unit is scanned once, in candidate order, at the weight it was bound with.
    let bound: Vec<(String, usize)> = candidate
        .units
        .iter()
        .map(|u| (u.location.clone(), u.weight()))
        .collect();
    assert_eq!(scanner.seen.concat(), bound);
    // A unit heavier than the limit fits no batch: the scan refuses rather than hand the
    // scanner a batch over it.
    f.write("data/large.txt", &filler("large", LIMIT + 1));
    let head = f.commit("one large file");
    let candidate = git.candidate(&f.policy, REPOSITORY, &head, &[]).unwrap();
    let mut scanner = Batches::default();
    let refused = evidence::check(&f.policy, &candidate, &f.key, &mut scanner)
        .expect_err("a unit over the batch limit must refuse the scan")
        .to_string();
    assert!(refused.contains("batch limit"), "{refused}");
    assert!(scanner.sizes().iter().all(|size| *size <= LIMIT));
}

#[test]
fn small_candidate_receipt_unchanged() {
    let (f, head) = small();
    let candidate = Git::new(f.dir.path())
        .unwrap()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    assert_eq!(candidate.binding.objects_digest, SMALL_OBJECTS_DIGEST);
    let mut scanner = Batches::default();
    let receipt = evidence::check(&f.policy, &candidate, &f.key, &mut scanner).unwrap();
    assert_eq!(scanner.seen.len(), 1);
    assert_eq!(
        serde_json::to_string(&receipt.payload.results).unwrap(),
        SMALL_RESULTS
    );
    // The unbatched scan: every unit in memory and one `run`, as before batches.
    let units = candidate.units.read_all().unwrap();
    let manifest: Vec<_> = units
        .iter()
        .map(|u| (&u.location, digest(&u.bytes), u.workflow))
        .collect();
    assert_eq!(
        digest(&serde_json::to_vec(&manifest).unwrap()),
        SMALL_OBJECTS_DIGEST
    );
    let mut unbatched = Batches::default();
    let report = scan::run(&f.policy, REPOSITORY, &units, &mut unbatched).unwrap();
    assert_eq!(scanner.seen, unbatched.seen);
    assert_eq!(receipt.payload.results, report.results);
    // Inside one batch at a lowered limit, the receipt is the same to the byte.
    let lowered = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let mut scanner = Batches::default();
    let again = evidence::check(&f.policy, &lowered, &f.key, &mut scanner).unwrap();
    assert_eq!(scanner.seen.len(), 1);
    assert_eq!(
        serde_json::to_vec(&again).unwrap(),
        serde_json::to_vec(&receipt).unwrap()
    );
}

#[test]
fn oversized_blob_still_refused() {
    let f = Fixture::new();
    f.write("large.bin", &vec![b'x'; MAX_BLOB + 1]);
    let head = f.commit("one blob over the per-blob limit");
    for git in [Git::new(f.dir.path()).unwrap(), f.limited()] {
        let refused = git
            .candidate(&f.policy, REPOSITORY, &head, &[])
            .err()
            .expect("a blob over the per-blob limit must be refused")
            .to_string();
        assert!(refused.contains("blob exceeds scan limit"), "{refused}");
    }
}
