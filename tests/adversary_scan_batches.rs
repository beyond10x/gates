//! Adversary cases for `story:scan-bounded-batches`: units read lazily a batch at a time
//! must be the bytes the build bound, read against the predecessor the build chose, each
//! scanned exactly once, with the findings and receipts an unbatched scan gives.
use b10x_gates::{
    BOT_EMAIL, BOT_NAME, digest, evidence,
    git::{BATCH_LIMIT, Git, Unit, Units},
    policy::{Policy, Repository, Signer},
    scan::{self, Report, SecretFinding, SecretScanner},
};
use ed25519_dalek::SigningKey;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

const REPOSITORY: &str = "example/repository";

/// The lowered batch limit, through the library constructor only.
const LIMIT: usize = 64 * 1024;

/// A line the fake secret scanner reports, as Gitleaks reports a credential.
const SECRET_MARK: &str = "fixture-secret-marker";

/// One unit as the scanner was handed it: location, digest of its bytes, digest of its
/// predecessor's bytes, and its weight (bytes plus predecessor).
type Seen = (String, String, Option<String>, usize);

/// Records every batch and reports a secret on every line equal to `SECRET_MARK`, in unit
/// order, as an order-preserving scanner would.
#[derive(Default)]
struct Recorder {
    seen: Vec<Vec<Seen>>,
}

impl SecretScanner for Recorder {
    fn scan(&mut self, units: &[Unit]) -> anyhow::Result<Vec<SecretFinding>> {
        self.seen.push(
            units
                .iter()
                .map(|u| {
                    (
                        u.location.clone(),
                        digest(&u.bytes),
                        u.inherited.as_deref().map(digest),
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

impl Recorder {
    fn sizes_within(&self, limit: usize) -> bool {
        self.seen
            .iter()
            .all(|batch| batch.iter().map(|v| v.3).sum::<usize>() <= limit)
    }

    fn locations(&self) -> Vec<String> {
        self.seen.concat().into_iter().map(|v| v.0).collect()
    }

    fn of(&self, location: &str) -> Vec<(String, Option<String>)> {
        self.seen
            .concat()
            .into_iter()
            .filter(|v| v.0 == location)
            .map(|v| (v.1, v.2))
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
        let key = SigningKey::from_bytes(&[23; 32]);
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

    fn blob(&self, rev: &str, path: &str) -> String {
        git(self.root(), &["rev-parse", &format!("{rev}:{path}")])
    }

    /// Write `bytes` as a loose blob without touching the index or any ref.
    fn object(&self, bytes: &[u8]) -> String {
        let scratch = self.root().join(".git").join("adversary-blob");
        fs::write(&scratch, bytes).unwrap();
        let oid = git(
            self.root(),
            &[
                "hash-object",
                "-w",
                "--no-filters",
                scratch.to_str().unwrap(),
            ],
        );
        fs::remove_file(scratch).unwrap();
        oid
    }

    fn loose(&self, oid: &str) -> PathBuf {
        self.root()
            .join(".git/objects")
            .join(&oid[..2])
            .join(&oid[2..])
    }

    /// Put the loose object file of `with` where the object `victim` is stored: Git then
    /// answers `victim` with `with`'s bytes, as a store changed under the scan would.
    fn swap(&self, victim: &str, with: &str) {
        let target = self.loose(victim);
        assert!(target.is_file(), "{victim} is not a loose object");
        fs::remove_file(&target).unwrap();
        fs::copy(self.loose(with), &target).unwrap();
    }

    fn limited(&self) -> Git {
        Git::with_batch_limit(self.root(), LIMIT).unwrap()
    }

    fn unlimited(&self) -> Git {
        Git::new(self.root()).unwrap()
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

/// `count` complete lines that break no rule, each ending in a newline.
fn lines(seed: &str, count: usize) -> String {
    (0..count)
        .map(|i| format!("safe filler {seed} line {i:06}\n"))
        .collect()
}

fn findings(report: &Report) -> Vec<(String, String, usize)> {
    report
        .findings
        .iter()
        .map(|v| (v.rule.clone(), v.location.clone(), v.line))
        .collect()
}

fn held(location: &str, bytes: usize, inherited: Option<usize>) -> Unit {
    Unit {
        location: location.into(),
        bytes: vec![b'x'; bytes],
        workflow: false,
        inherited: inherited.map(|n| vec![b'y'; n]),
    }
}

/// `notes.md` added clean, then edited to introduce the forbidden literal on line 2. The
/// predecessor is exactly as long as `"{denied}\n"`.
fn edited(f: &Fixture) -> (String, String) {
    let denied = f.denied();
    f.write(
        "notes.md",
        format!("{}\n", "x".repeat(denied.len())).as_bytes(),
    );
    let parent = f.commit("notes");
    f.write("notes.md", format!("safe line\n{denied}\n").as_bytes());
    let head = f.commit("edit notes");
    (parent, head)
}

/// The predecessor was added inside the candidate, so it is also a unit whose digest binds it.
#[test]
fn a_predecessor_swapped_between_build_and_scan_refuses() {
    let f = Fixture::new();
    let (parent, head) = edited(&f);
    let predecessor = f.blob(&parent, "notes.md");
    let candidate = f
        .unlimited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let before = scan::run_batches(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut Recorder::default(),
    )
    .unwrap();
    let introduced = (
        "private-identifiers".to_owned(),
        "file:notes.md".to_owned(),
        2,
    );
    assert!(
        findings(&before).contains(&introduced),
        "{:?}",
        findings(&before)
    );
    // Same length as the bound predecessor, now carrying the introduced line.
    let fake = f.object(format!("{}\n", f.denied()).as_bytes());
    f.swap(&predecessor, &fake);
    match scan::run_batches(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut Recorder::default(),
    ) {
        Err(_) => {}
        Ok(after) => assert!(
            findings(&after).contains(&introduced),
            "a predecessor changed after the build hid the introduced line: {:?}",
            findings(&after)
        ),
    }
    assert!(
        evidence::check(&f.policy, &candidate, &f.key, &mut Recorder::default()).is_err(),
        "a receipt was signed although the introduced line was never reported"
    );
}

/// The common case: a file that already existed at the adoption baseline is edited. Its
/// predecessor is in the baseline tree, so no unit of the candidate binds those bytes.
#[test]
fn a_baseline_predecessor_swapped_between_build_and_scan_refuses() {
    let mut f = Fixture::new();
    let denied = f.denied();
    f.write(
        "notes.md",
        format!("{}\n", "x".repeat(denied.len())).as_bytes(),
    );
    let baseline = f.commit("notes at the baseline");
    f.policy.repositories.get_mut(REPOSITORY).unwrap().baseline = baseline.clone();
    f.write("notes.md", format!("safe line\n{denied}\n").as_bytes());
    let head = f.commit("edit notes");
    let predecessor = f.blob(&baseline, "notes.md");
    let candidate = f
        .unlimited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let introduced = (
        "private-identifiers".to_owned(),
        "file:notes.md".to_owned(),
        2,
    );
    let before = scan::run_batches(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut Recorder::default(),
    )
    .unwrap();
    assert_eq!(findings(&before), vec![introduced.clone()]);
    // Same length as the bound predecessor, now carrying the introduced line.
    let fake = f.object(format!("{denied}\n").as_bytes());
    f.swap(&predecessor, &fake);
    match scan::run_batches(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut Recorder::default(),
    ) {
        Err(_) => {}
        Ok(after) => assert!(
            findings(&after).contains(&introduced),
            "a predecessor changed after the build hid the introduced line: {:?}",
            findings(&after)
        ),
    }
    assert!(
        evidence::check(&f.policy, &candidate, &f.key, &mut Recorder::default()).is_err(),
        "a receipt was signed although the introduced line was never reported"
    );
}

#[test]
fn the_units_own_object_swapped_or_removed_between_build_and_scan_refuses() {
    for change in ["same length", "longer", "removed"] {
        let f = Fixture::new();
        let (_, head) = edited(&f);
        let current = f.blob(&head, "notes.md");
        let candidate = f
            .limited()
            .candidate(&f.policy, REPOSITORY, &head, &[])
            .unwrap();
        let denied = f.denied();
        match change {
            "same length" => {
                let fake =
                    f.object(format!("safe line\n{}\n", "y".repeat(denied.len())).as_bytes());
                f.swap(&current, &fake);
            }
            "longer" => {
                let fake =
                    f.object(format!("safe line\n{}\n", "y".repeat(denied.len() + 9)).as_bytes());
                f.swap(&current, &fake);
            }
            _ => fs::remove_file(f.loose(&current)).unwrap(),
        }
        let mut scanner = Recorder::default();
        let refused = scan::run_batches(&f.policy, REPOSITORY, &candidate.units, &mut scanner);
        assert!(
            refused.is_err(),
            "{change}: the scan read bytes nobody bound"
        );
        assert!(
            scanner
                .locations()
                .iter()
                .all(|location| location != "file:notes.md"),
            "{change}: the scanner was handed the changed unit"
        );
    }
}

#[test]
fn a_predecessor_removed_between_build_and_scan_refuses() {
    let f = Fixture::new();
    let (parent, head) = edited(&f);
    let predecessor = f.blob(&parent, "notes.md");
    let candidate = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    fs::remove_file(f.loose(&predecessor)).unwrap();
    let refused = scan::run_batches(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut Recorder::default(),
    );
    assert!(
        refused.is_err(),
        "the scan went on without the predecessor it bound"
    );
}

#[test]
fn replace_refs_planted_between_build_and_scan_change_nothing() {
    let f = Fixture::new();
    let (parent, head) = edited(&f);
    let predecessor = f.blob(&parent, "notes.md");
    let current = f.blob(&head, "notes.md");
    let candidate = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let denied = f.denied();
    let hiding = f.object(format!("{denied}\n").as_bytes());
    let clean = f.object(format!("safe line\n{}\n", "y".repeat(denied.len())).as_bytes());
    git(f.root(), &["replace", &predecessor, &hiding]);
    git(f.root(), &["replace", &current, &clean]);
    match scan::run_batches(
        &f.policy,
        REPOSITORY,
        &candidate.units,
        &mut Recorder::default(),
    ) {
        Err(_) => {}
        Ok(report) => assert!(
            findings(&report).contains(&(
                "private-identifiers".to_owned(),
                "file:notes.md".to_owned(),
                2
            )),
            "a replace ref hid the introduced line: {:?}",
            findings(&report)
        ),
    }
    assert!(evidence::check(&f.policy, &candidate, &f.key, &mut Recorder::default()).is_err());
}

/// One path edited in five commits, each version about a third of the limit, so its
/// versions land in different batches, each read against its own predecessor.
#[test]
fn every_version_is_scanned_once_against_its_own_predecessor_across_batches() {
    let f = Fixture::new();
    let denied = f.denied();
    let versions = [
        lines("one", 700),
        format!("{}{denied}\n", lines("one", 700)),
        format!("{}{denied}\n", lines("three", 700)),
        format!("{}{denied}\n{SECRET_MARK}\n", lines("four", 700)),
        format!("{}{denied}\n{SECRET_MARK}\n", lines("five", 700)),
    ];
    let mut head = String::new();
    for (i, version) in versions.iter().enumerate() {
        f.write("data/edit.txt", version.as_bytes());
        head = f.commit(&format!("version {i}"));
    }
    let candidate = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let mut scanner = Recorder::default();
    let report = scan::run_batches(&f.policy, REPOSITORY, &candidate.units, &mut scanner).unwrap();
    assert!(scanner.seen.len() >= 4, "{} batches", scanner.seen.len());
    let d = |v: &String| digest(v.as_bytes());
    assert_eq!(
        scanner.of("file:data/edit.txt"),
        vec![
            (d(&versions[0]), None),
            (d(&versions[1]), Some(d(&versions[0]))),
            (d(&versions[2]), Some(d(&versions[1]))),
            (d(&versions[3]), Some(d(&versions[2]))),
            (d(&versions[4]), Some(d(&versions[3]))),
        ]
    );
    let bound: Vec<String> = candidate.units.iter().map(|u| u.location.clone()).collect();
    assert_eq!(scanner.locations(), bound);
    assert_eq!(
        findings(&report),
        vec![
            (
                "private-identifiers".into(),
                "file:data/edit.txt".into(),
                701
            ),
            ("secrets".into(), "file:data/edit.txt".into(), 702),
        ]
    );
    assert_eq!(report.results["private-identifiers"].findings, 1);
    assert_eq!(report.results["secrets"].findings, 1);
}

/// Rule findings and secrets in the first and the last batch: one unbatched run reports
/// every rule finding in unit order, then every secret, and so must the batched one.
#[test]
fn findings_order_and_counts_equal_an_unbatched_run() {
    let f = Fixture::new();
    let denied = f.denied();
    f.write("a.md", format!("{denied}\n{SECRET_MARK}\n").as_bytes());
    f.commit("first");
    for middle in ["b1", "b2", "b3"] {
        f.write(&format!("{middle}.txt"), lines(middle, 1500).as_bytes());
        f.commit(middle);
    }
    f.write(
        "c.md",
        format!("safe\n{SECRET_MARK}\n{denied}\n").as_bytes(),
    );
    let head = f.commit("last");
    let limited = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let mut scanner = Recorder::default();
    let batched = scan::run_batches(&f.policy, REPOSITORY, &limited.units, &mut scanner).unwrap();
    assert!(scanner.seen.len() >= 3, "{} batches", scanner.seen.len());
    let expected: Vec<(String, String, usize)> = vec![
        ("private-identifiers".into(), "file:a.md".into(), 1),
        ("private-identifiers".into(), "file:c.md".into(), 3),
        ("secrets".into(), "file:a.md".into(), 2),
        ("secrets".into(), "file:c.md".into(), 2),
    ];
    assert_eq!(findings(&batched), expected);
    let unbatched = scan::run(
        &f.policy,
        REPOSITORY,
        &limited.units.read_all().unwrap(),
        &mut Recorder::default(),
    )
    .unwrap();
    assert_eq!(findings(&unbatched), expected);
    assert_eq!(batched.results, unbatched.results);
    let whole = f
        .unlimited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let mut one = Recorder::default();
    let report = scan::run_batches(&f.policy, REPOSITORY, &whole.units, &mut one).unwrap();
    assert_eq!(one.seen.len(), 1);
    assert_eq!(findings(&report), expected);
    assert_eq!(report.results, batched.results);
    assert_eq!(whole.binding, limited.binding);
}

#[test]
fn batches_are_cut_at_the_exact_limit_with_predecessors_counted() {
    let f = Fixture::new();
    let git = Git::with_batch_limit(f.root(), 100).unwrap();
    let mut units = Units::new(&git);
    units.push(held("a", 30, Some(30)));
    units.push(held("b", 40, None));
    units.push(held("c", 1, None));
    units.push(held("d", 100, None));
    units.push(held("e", 0, None));
    let mut scanner = Recorder::default();
    scan::run_batches(&f.policy, REPOSITORY, &units, &mut scanner).unwrap();
    let cut: Vec<Vec<(String, usize)>> = scanner
        .seen
        .iter()
        .map(|batch| batch.iter().map(|v| (v.0.clone(), v.3)).collect())
        .collect();
    assert_eq!(
        cut,
        vec![
            vec![("a".to_owned(), 60), ("b".to_owned(), 40)],
            vec![("c".to_owned(), 1)],
            vec![("d".to_owned(), 100), ("e".to_owned(), 0)],
        ]
    );
    // No units: one empty batch, one scanner invocation, as an unbatched run.
    let mut scanner = Recorder::default();
    scan::run_batches(&f.policy, REPOSITORY, &Units::new(&git), &mut scanner).unwrap();
    assert_eq!(scanner.seen, vec![Vec::<Seen>::new()]);
    // One over the limit only with its predecessor: refused before any batch is scanned.
    for over in [held("f", 101, None), held("g", 51, Some(50))] {
        let mut units = Units::new(&git);
        units.push(held("ok", 10, None));
        units.push(over);
        let mut scanner = Recorder::default();
        let refused = scan::run_batches(&f.policy, REPOSITORY, &units, &mut scanner)
            .err()
            .expect("a unit over the limit must refuse")
            .to_string();
        assert!(refused.contains("batch limit"), "{refused}");
        assert!(
            scanner.seen.is_empty(),
            "{} batches scanned",
            scanner.seen.len()
        );
    }
}

#[test]
fn a_changed_file_over_the_limit_only_with_its_predecessor_is_refused() {
    let f = Fixture::new();
    f.write("big.txt", lines("old", 1300).as_bytes());
    f.commit("old");
    f.write("big.txt", lines("new", 1300).as_bytes());
    let head = f.commit("new");
    let candidate = f
        .limited()
        .candidate(&f.policy, REPOSITORY, &head, &[])
        .unwrap();
    let unit = candidate
        .units
        .iter()
        .rfind(|u| u.location == "file:big.txt")
        .unwrap();
    assert!(unit.length <= LIMIT && unit.weight() > LIMIT);
    let mut scanner = Recorder::default();
    assert!(scan::run_batches(&f.policy, REPOSITORY, &candidate.units, &mut scanner).is_err());
    assert!(scanner.sizes_within(LIMIT));
}

/// Six commits, one new file each, about a third of the limit; a receipt for the third.
fn six(f: &Fixture) -> Vec<String> {
    (1..=6)
        .map(|i| {
            f.write(
                &format!("data/c{i}.txt"),
                lines(&format!("c{i}"), 1100).as_bytes(),
            );
            f.commit(&format!("commit {i}"))
        })
        .collect()
}

#[test]
fn ancestor_reuse_scans_exactly_the_uncovered_commits_across_batches() {
    let f = Fixture::new();
    let commits = six(&f);
    let git = f.limited();
    let ancestor = git
        .candidate(&f.policy, REPOSITORY, &commits[2], &[])
        .unwrap();
    let retained = evidence::check(&f.policy, &ancestor, &f.key, &mut Recorder::default()).unwrap();
    let candidate = git
        .candidate(&f.policy, REPOSITORY, &commits[5], &[])
        .unwrap();
    let mut scanner = Recorder::default();
    let checked = evidence::check_reusing(
        &f.policy,
        &git,
        &candidate,
        std::slice::from_ref(&retained),
        &f.key,
        &mut scanner,
    )
    .unwrap();
    assert_eq!(checked.reused.as_deref(), Some(commits[2].as_str()));
    assert_eq!(checked.scanned_commits, 3);
    assert!(scanner.seen.len() > 1, "{} batches", scanner.seen.len());
    let expected: Vec<String> = (4..=6)
        .flat_map(|i| {
            [
                format!("filename:data/c{i}.txt"),
                format!("file:data/c{i}.txt"),
                format!("commit:{}", commits[i - 1]),
            ]
        })
        .collect();
    assert_eq!(scanner.locations(), expected);
    evidence::verify(&f.policy, &candidate, &checked.receipt).unwrap();
    // The same receipt as a full scan of the whole candidate signs.
    let full = evidence::check(&f.policy, &candidate, &f.key, &mut Recorder::default()).unwrap();
    assert_eq!(
        serde_json::to_vec(&full).unwrap(),
        serde_json::to_vec(&checked.receipt).unwrap()
    );
}

#[test]
fn a_tag_unit_in_the_last_batch_is_scanned_after_ancestor_reuse() {
    let f = Fixture::new();
    let commits = six(&f);
    let denied = f.denied();
    git(
        f.root(),
        &["tag", "-a", "inner", "-m", &format!("safe\n\n{denied}")],
    );
    git(
        f.root(),
        &["tag", "-a", "outer", "refs/tags/inner", "-m", "outer safe"],
    );
    let inner = git(f.root(), &["rev-parse", "refs/tags/inner"]);
    let outer = git(f.root(), &["rev-parse", "refs/tags/outer"]);
    let raw = git(f.root(), &["cat-file", "tag", &inner]);
    let line = raw.lines().position(|v| v == denied).unwrap() + 1;
    let git = f.limited();
    let ancestor = git
        .candidate(&f.policy, REPOSITORY, &commits[4], &[])
        .unwrap();
    let retained = evidence::check(&f.policy, &ancestor, &f.key, &mut Recorder::default()).unwrap();
    let candidate = git
        .candidate(&f.policy, REPOSITORY, &commits[5], &["outer".to_owned()])
        .unwrap();
    let mut scanner = Recorder::default();
    let report = scan::run_batches(&f.policy, REPOSITORY, &candidate.units, &mut scanner).unwrap();
    let last = scanner.seen.last().unwrap();
    let tail: Vec<String> = last.iter().map(|v| v.0.clone()).collect();
    let tags = [
        "tag-ref".to_owned(),
        format!("tag:{outer}"),
        format!("tag:{inner}"),
    ];
    assert!(tail.ends_with(&tags), "{tail:?}");
    assert!(scanner.seen.len() > 1);
    assert_eq!(
        findings(&report),
        vec![(
            "private-identifiers".to_owned(),
            format!("tag:{inner}"),
            line
        )]
    );
    let mut scanner = Recorder::default();
    let refused = evidence::check_reusing(
        &f.policy,
        &git,
        &candidate,
        std::slice::from_ref(&retained),
        &f.key,
        &mut scanner,
    )
    .err()
    .expect("a finding in a tag unit must refuse the receipt")
    .to_string();
    assert!(refused.contains("common checks failed"), "{refused}");
    let scanned = scanner.locations();
    assert!(scanned.contains(&format!("tag:{inner}")), "{scanned:?}");
    assert!(!scanned.contains(&format!("commit:{}", commits[4])));
}

#[test]
fn staged_and_historical_are_cut_into_batches_and_keep_inheritance() {
    let f = Fixture::new();
    let denied = f.denied();
    f.write("keep.md", format!("old\n{denied}\n").as_bytes());
    f.commit("keep");
    for i in 0..5 {
        f.write(
            &format!("data/s{i}.txt"),
            lines(&format!("s{i}"), 700).as_bytes(),
        );
    }
    f.write("keep.md", format!("new\n{denied}\n").as_bytes());
    f.write("z-last.md", format!("{denied}\n").as_bytes());
    git(f.root(), &["add", "-A"]);
    let git = f.limited();
    let mut scanner = Recorder::default();
    let report =
        scan::run_batches(&f.policy, REPOSITORY, &git.staged().unwrap(), &mut scanner).unwrap();
    assert!(scanner.seen.len() > 1, "{} batches", scanner.seen.len());
    assert!(
        scanner
            .seen
            .last()
            .unwrap()
            .iter()
            .any(|v| v.0 == "file:z-last.md")
    );
    assert_eq!(
        findings(&report),
        vec![(
            "private-identifiers".to_owned(),
            "file:z-last.md".to_owned(),
            1
        )]
    );
    let unbatched = scan::run(
        &f.policy,
        REPOSITORY,
        &f.unlimited().staged().unwrap().read_all().unwrap(),
        &mut Recorder::default(),
    )
    .unwrap();
    assert_eq!(findings(&unbatched), findings(&report));
    let head = f.commit("staged");
    let mut scanner = Recorder::default();
    let report = scan::run_batches(
        &f.policy,
        REPOSITORY,
        &git.historical(&head).unwrap(),
        &mut scanner,
    )
    .unwrap();
    assert!(scanner.seen.len() > 1, "{} batches", scanner.seen.len());
    assert_eq!(
        findings(&report),
        vec![
            (
                "private-identifiers".to_owned(),
                "file:keep.md".to_owned(),
                2
            ),
            (
                "private-identifiers".to_owned(),
                "file:z-last.md".to_owned(),
                1
            ),
        ]
    );
}

#[test]
fn the_batch_limit_can_only_be_lowered() {
    let f = Fixture::new();
    assert!(Git::with_batch_limit(f.root(), BATCH_LIMIT + 1).is_err());
    assert!(Git::with_batch_limit(f.root(), usize::MAX).is_err());
    assert!(Git::with_batch_limit(f.root(), 0).is_err());
    Git::with_batch_limit(f.root(), BATCH_LIMIT).unwrap();
}
