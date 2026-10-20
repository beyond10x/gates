//! Adversary pass 2 on `story:api-protection-writes` (`gates.delivery.BotApi`,
//! `src/protection.rs`), against correction round 2.
//!
//! Every binary run here has no bot configuration (`B10X_BOT_CONFIG` names an absent file)
//! and `PATH` names an empty directory, so no `gh` can run and nothing reaches GitHub. A
//! bounded case runs the binary under `timeout` and an address-space cap, with core files
//! off.
use b10x_gates::policy::Policy;
use b10x_gates::protection::gh_api_refusal;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

const OWNERS: &str = "ruleset and branch protection changes are the owner's";
const ABSENT_BOT: &str = "absent-bot.json";

/// Wall-clock bound for judging a 128 KiB input. A guard whose work is linear in its input
/// judges one in well under a second, even in a debug build.
const BOUND: Duration = Duration::from_secs(20);

struct Run {
    ok: bool,
    code: Option<i32>,
    stderr: String,
    elapsed: Duration,
}

struct Sandbox {
    dir: tempfile::TempDir,
    policy: PathBuf,
}

impl Sandbox {
    /// A sandbox with a synthetic owner-only policy, so a request the guard admits passes
    /// the private-rule scan and reaches the token step.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("bin")).unwrap();
        let policy = dir.path().join("policy.json");
        let document = Policy {
            version: 1,
            nonce: "synthetic-policy-nonce-for-adversary-pass-2".into(),
            forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
            forbidden_patterns: vec![],
            allow_patterns: vec![],
            repositories: BTreeMap::new(),
            signers: BTreeMap::new(),
            exceptions: vec![],
        };
        fs::write(&policy, serde_json::to_vec(&document).unwrap()).unwrap();
        fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        Self { dir, policy }
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self, name: &str, bytes: &[u8]) {
        fs::write(self.path().join(name), bytes).unwrap();
    }

    /// `b10x-gates --repo <sandbox> gh -- api <args>` under a 60 s timeout and a 512 MiB
    /// address-space cap.
    fn capped_gh(&self, args: &[&str]) -> Run {
        let config = self.path().join("config");
        let mut command = Command::new("/usr/bin/timeout");
        command
            .args([
                "60",
                "/usr/bin/prlimit",
                "--as=536870912",
                "--core=0",
                "--",
                env!("CARGO_BIN_EXE_b10x-gates"),
                "--repo",
            ])
            .arg(self.path())
            .args(["gh", "--", "api"])
            .args(args)
            .current_dir(self.path())
            .env("B10X_GATES_POLICY", &self.policy)
            .env("XDG_CONFIG_HOME", &config)
            .env("B10X_BOT_CONFIG", config.join(ABSENT_BOT))
            .env("B10X_BOT_KEY", config.join("absent-key.pem"))
            .env("PATH", self.path().join("bin"));
        let started = Instant::now();
        let output = command.output().unwrap();
        Run {
            ok: output.status.success(),
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            elapsed: started.elapsed(),
        }
    }
}

/// The run ended as an ordinary error within `BOUND` and reached the token step: the guard
/// judged the input and admitted it.
fn admitted_within_the_bound(run: &Run) {
    let stderr: String = run.stderr.chars().take(400).collect();
    assert!(
        run.elapsed < BOUND,
        "judged in {:?}, bound {BOUND:?}; exit {:?}; stderr: {stderr}",
        run.elapsed,
        run.code
    );
    assert_eq!(run.code, Some(1), "exit {:?}; stderr: {stderr}", run.code);
    assert!(!run.ok, "{stderr}");
    assert!(!run.stderr.contains(OWNERS), "{stderr}");
    assert!(run.stderr.contains(ABSENT_BOT), "{stderr}");
}

/// About 128 KiB of `unit` repeated.
fn repeated(unit: &str) -> Vec<u8> {
    unit.repeat(128 * 1024 / unit.len()).into_bytes()
}

// --- Bounded work (brief, pass 2: "time ... may still be quadratic") ----------------------

/// Brief: the guard never fails on a huge file within reason; round 2 (A7) says the work
/// stays linear in the input. A 128 KiB `--input` file of `repos/` repeated with no
/// separator carries no protection path, so it is admitted, within `BOUND`.
#[test]
fn input_file_of_repeated_repos_segments_is_judged_within_bounded_time() {
    let sandbox = Sandbox::new();
    sandbox.file("body.json", &repeated("repos/"));
    let run = sandbox.capped_gh(&["repos/example/example/issues", "--input", "body.json"]);
    admitted_within_the_bound(&run);
}

/// The control for the case above: a file of the same size without `repos` is admitted
/// within the same bound and cap, so neither is what fails.
#[test]
fn plain_input_file_of_the_same_size_is_judged_within_the_same_bound() {
    let sandbox = Sandbox::new();
    sandbox.file("body.json", &repeated("abcde/"));
    let run = sandbox.capped_gh(&["repos/example/example/issues", "--input", "body.json"]);
    admitted_within_the_bound(&run);
}

// --- The check order the ESS states ------------------------------------------------------

/// ESS `gates.delivery.BotApi`: "Outcomes are taken in declaration order over every
/// argument and named file", and `standard-input` is declared before `unreadable-file`.
/// A request that names an unreadable file and then standard input is refused for
/// standard input.
#[test]
fn standard_input_is_named_before_an_earlier_unreadable_file() {
    let args: Vec<String> = [
        "api",
        "repos/example/example/issues",
        "-F",
        "note=@absent.txt",
        "--input",
        "-",
    ]
    .iter()
    .map(|a| (*a).to_owned())
    .collect();
    let refusal = gh_api_refusal(&args, |_| {
        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    })
    .expect("refused");
    assert!(refusal.contains(OWNERS), "{refusal}");
    assert!(refusal.contains("standard input"), "{refusal}");
}
