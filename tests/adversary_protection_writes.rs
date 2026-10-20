//! Adversary pass 1 on `story:api-protection-writes` (`gates.delivery.BotApi`,
//! `src/protection.rs`). Each case states the contract it holds the guard to: the story's
//! `## Acceptance`, the outcomes in `ess/domains/delivery.yaml`, or the module
//! documentation.
//!
//! Every run here has no bot configuration (`B10X_BOT_CONFIG` names an absent file) and
//! `PATH` names an empty directory, so no `gh` can run and nothing reaches GitHub. An error
//! naming the absent bot configuration reached the token step; a refusal naming
//! `OWNERS` came from the guard.
use b10x_gates::policy::Policy;
use b10x_gates::protection::{gh_api_refusal, protection_write};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

const OWNERS: &str = "ruleset and branch protection changes are the owner's";
const ABSENT_BOT: &str = "absent-bot.json";

/// The address-space cap a bounded-memory case runs the binary under, in bytes. A guard
/// whose memory is linear in its input judges a 256 KiB input far below it.
const CAP: &str = "--as=536870912";

struct Run {
    ok: bool,
    code: Option<i32>,
    stderr: String,
}

struct Sandbox {
    dir: tempfile::TempDir,
    policy: Option<PathBuf>,
}

impl Sandbox {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("bin")).unwrap();
        Self { dir, policy: None }
    }

    /// A synthetic owner-only policy, so a case the guard admits passes the private-rule
    /// scan and reaches the token step.
    fn with_policy(mut self) -> Self {
        let path = self.dir.path().join("policy.json");
        let policy = Policy {
            version: 1,
            nonce: "synthetic-policy-nonce-for-adversary-test".into(),
            forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
            forbidden_patterns: vec![],
            allow_patterns: vec![],
            repositories: BTreeMap::new(),
            signers: BTreeMap::new(),
            exceptions: vec![],
        };
        fs::write(&path, serde_json::to_vec(&policy).unwrap()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        self.policy = Some(path);
        self
    }

    fn path(&self) -> &Path {
        self.dir.path()
    }

    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path().join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    /// The binary, or with `capped` the binary under `timeout` and an address-space cap.
    fn command(&self, capped: bool) -> Command {
        let config = self.path().join("config");
        let binary = env!("CARGO_BIN_EXE_b10x-gates");
        let mut command = if capped {
            let mut command = Command::new("/usr/bin/timeout");
            command
                .args(["120", "/usr/bin/prlimit", CAP, "--core=0", "--"])
                .arg(binary);
            command
        } else {
            Command::new(binary)
        };
        command
            .current_dir(self.path())
            .env_remove("B10X_GATES_POLICY")
            .env("XDG_CONFIG_HOME", &config)
            .env("B10X_BOT_CONFIG", config.join(ABSENT_BOT))
            .env("B10X_BOT_KEY", config.join("absent-key.pem"))
            .env("PATH", self.path().join("bin"));
        if let Some(policy) = &self.policy {
            command.env("B10X_GATES_POLICY", policy);
        }
        command
    }

    fn run(&self, mut command: Command) -> Run {
        let output = command.output().unwrap();
        Run {
            ok: output.status.success(),
            code: output.status.code(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn api_command(&self, capped: bool, method: &str, path: &str, input: Option<&[u8]>) -> Run {
        let mut command = self.command(capped);
        command
            .args(["api", "--method", method, "--path", path, "--output"])
            .arg(self.path().join("response.json"));
        if let Some(bytes) = input {
            command.arg("--input").arg(self.file("request.json", bytes));
        }
        self.run(command)
    }

    fn api(&self, method: &str, path: &str, input: Option<&[u8]>) -> Run {
        self.api_command(false, method, path, input)
    }

    fn gh_command(&self, capped: bool, args: &[&str]) -> Run {
        let mut command = self.command(capped);
        command
            .arg("--repo")
            .arg(self.path())
            .args(["gh", "--", "api"])
            .args(args);
        self.run(command)
    }

    fn gh(&self, args: &[&str]) -> Run {
        self.gh_command(false, args)
    }
}

/// Refused by the guard, naming `named`.
fn refused(run: &Run, named: &str) {
    assert!(!run.ok, "{}", run.stderr);
    assert!(run.stderr.contains(OWNERS), "{}", run.stderr);
    assert!(run.stderr.contains(named), "{named}: {}", run.stderr);
    assert!(!run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
}

/// Not refused by the guard: the run went on to the token step.
fn reached_token(run: &Run) {
    assert!(!run.ok, "{}", run.stderr);
    assert!(!run.stderr.contains(OWNERS), "{}", run.stderr);
    assert!(run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
}

/// A capped run ended as an ordinary error (exit 1), not a signal, a timeout or an
/// allocation failure, and the guard judged the input: refused or reached the token step.
fn judged_within_the_cap(run: &Run) {
    assert_eq!(
        run.code,
        Some(1),
        "the guard did not finish within the cap; stderr: {}",
        run.stderr.chars().take(400).collect::<String>()
    );
    assert!(
        !run.stderr.contains("memory allocation"),
        "{}",
        run.stderr.chars().take(400).collect::<String>()
    );
    reached_token(run);
}

/// A capped run ended as an ordinary error (exit 1), not a signal, a timeout or an
/// allocation failure, and the guard refused the input as undecodable: the coordinator's
/// decision in correction round 2, finding A7, refuses text still changing after 8
/// percent-decodings.
fn refused_as_undecodable_within_the_cap(run: &Run) {
    assert_eq!(
        run.code,
        Some(1),
        "the guard did not finish within the cap; stderr: {}",
        run.stderr.chars().take(400).collect::<String>()
    );
    assert!(
        !run.stderr.contains("memory allocation"),
        "{}",
        run.stderr.chars().take(400).collect::<String>()
    );
    refused(run, "cannot be decoded");
}

/// A percent-encoding nested `depth` times that decodes, one level per decoding, to `A`:
/// `%25` repeated, then `41`.
fn nested_percent(depth: usize) -> String {
    format!("%{}41", "25".repeat(depth))
}

// --- Reads and unrelated writes the contract keeps open ---------------------------------

/// Acceptance: "a GraphQL query that names none of them is not [refused]". An
/// introspection query names the input type `UpdateBranchProtectionRuleInput`, a read of
/// the schema, and no mutation; GraphQL names are case-sensitive.
#[test]
fn graphql_introspection_of_a_mutation_input_type_reaches_the_token_step() {
    let query = serde_json::json!({
        "query": "query { __type(name: \"UpdateBranchProtectionRuleInput\") { inputFields { name } } }",
    })
    .to_string();
    // An `--input` body is read by the private-rule scan after the guard, which needs a
    // policy before the token step is reached.
    reached_token(
        &Sandbox::new()
            .with_policy()
            .api("POST", "/graphql", Some(query.as_bytes())),
    );
}

/// ESS `gates.delivery.BotApi`: "A placeholder in an argument naming a GraphQL `query`
/// ... cannot be judged". A REST read of a file named `query.md` names no GraphQL query;
/// a `gh api` call on an unrelated endpoint stays open.
#[test]
fn gh_api_read_of_a_file_named_query_reaches_the_token_step() {
    let sandbox = Sandbox::new().with_policy();
    reached_token(&sandbox.gh(&["repos/{owner}/{repo}/contents/docs/query.md"]));
}

/// ESS `gates.delivery.BotApi`: an argument that holds a `Content-Encoding:` or
/// `Transfer-Encoding:` header text is refused. The coordinator's decision in correction
/// round 2, finding A3: the guard reads every argument for the header text rather than
/// parsing `-H`/`--header`, so no flag spelling is missed, and accepts that a comment body
/// mentioning the header is refused too.
#[test]
fn gh_api_comment_mentioning_content_encoding_is_refused() {
    let sandbox = Sandbox::new().with_policy();
    refused(
        &sandbox.gh(&[
            "repos/example/example/issues/1/comments",
            "-f",
            "body=Responses carry Content-Encoding: gzip when asked",
        ]),
        "Content-Encoding",
    );
}

/// Story proposal: only a write to a protection path is refused. A label named `50%`,
/// spelled `50%25` as GitHub expects, is an unrelated write whose path decodes once to a
/// valid text.
#[test]
fn api_write_to_a_label_with_an_encoded_percent_reaches_the_token_step() {
    reached_token(&Sandbox::new().api("PATCH", "/repos/example/example/labels/50%25", None));
}

// --- What a refusal says ----------------------------------------------------------------

/// Brief: the refusal never echoes a file's contents beyond the path. In a JSON input
/// the text after the path's escaped newline is the next line of the comment, not the
/// path.
#[test]
fn refusal_does_not_echo_file_text_after_a_json_newline_escape() {
    let sandbox = Sandbox::new();
    let newline = format!("{}n", char::from(92u8));
    let body = format!(
        "{{\"body\":\"Moved to repos/example/example/rulesets{newline}adversary-marker-text\"}}"
    );
    sandbox.file("body.json", body.as_bytes());
    let run = sandbox.gh(&[
        "repos/example/example/issues/1/comments",
        "--input",
        "body.json",
    ]);
    refused(&run, "/repos/example/example/rulesets");
    assert!(
        !run.stderr.contains("adversary-marker-text"),
        "file text beyond the path is echoed: {}",
        run.stderr
    );
}

/// ESS: outcomes are taken in declaration order, and `protection-path` is declared
/// before `body-encoding-header`; the story: "The refusal names the path". A request that
/// carries a protection path is refused naming it, whatever an earlier argument holds.
#[test]
fn gh_api_protection_path_after_an_encoding_header_is_named() {
    let run = Sandbox::new().gh(&[
        "-H",
        "Content-Encoding: identity",
        "-X",
        "PUT",
        "repos/example/example/rulesets/42",
    ]);
    refused(&run, "/repos/example/example/rulesets/42");
}

// --- Bounded work on inputs within reason -----------------------------------------------

/// Brief: the guard never fails on a very long path. A 64 KiB path nested in
/// percent-encoding is judged within a 512 MiB address space: refused as undecodable
/// (round 2, A7).
#[test]
fn nested_percent_encoding_in_an_api_path_is_judged_within_bounded_memory() {
    let path = format!(
        "/repos/example/example/issues/1/{}",
        nested_percent(32 * 1024)
    );
    let run = Sandbox::new().api_command(true, "PATCH", &path, None);
    refused_as_undecodable_within_the_cap(&run);
}

/// The control for the case above: a path of the same length without nesting is judged
/// under the same cap, so the cap alone is not what fails.
#[test]
fn plain_api_path_of_the_same_length_is_judged_within_the_same_cap() {
    let path = format!(
        "/repos/example/example/issues/1/{}",
        "a".repeat(64 * 1024 + 3)
    );
    let run = Sandbox::new().api_command(true, "PATCH", &path, None);
    judged_within_the_cap(&run);
}

/// Brief: the guard never fails on a huge file within reason. A 256 KiB `--input` file
/// nested in percent-encoding is judged within a 512 MiB address space: refused as
/// undecodable (round 2, A7).
#[test]
fn nested_percent_encoding_in_an_input_file_is_judged_within_bounded_memory() {
    let sandbox = Sandbox::new().with_policy();
    sandbox.file("body.json", nested_percent(128 * 1024).as_bytes());
    let run = sandbox.gh_command(
        true,
        &["repos/example/example/issues", "--input", "body.json"],
    );
    refused_as_undecodable_within_the_cap(&run);
}

/// The control for the case above: an input file of the same size without nesting.
#[test]
fn plain_input_file_of_the_same_size_is_judged_within_the_same_cap() {
    let sandbox = Sandbox::new().with_policy();
    sandbox.file("body.json", "a".repeat(256 * 1024 + 3).as_bytes());
    let run = sandbox.gh_command(
        true,
        &["repos/example/example/issues", "--input", "body.json"],
    );
    judged_within_the_cap(&run);
}

// --- Never panics -----------------------------------------------------------------------

/// Brief: the guard never panics on any input. Boundary paths, methods and bodies for
/// `api`, each judged without a panic; the protected ones are refused.
#[test]
fn protection_write_never_panics_on_boundary_inputs() {
    let mut invalid = b"{\"query\":\"".to_vec();
    invalid.extend_from_slice(&[0xff, 0xfe, 0x00, 0xc3, 0x28, 0xed, 0xa0, 0x80]);
    invalid.extend_from_slice(b"\"}");
    let long = format!("/repos/example/example/{}", "x/".repeat(50_000));
    let bodies: [&[u8]; 5] = [b"", b"%", &invalid, b"\xff\xfe", b"\x00\x00\xfe\xff"];
    for method in ["", "GET", "POST", "g\u{e9}t"] {
        for path in [
            "",
            "/",
            "%",
            "%%",
            "%2",
            "/graphql%",
            "/graphql?%",
            "//",
            "\\",
            "/..",
            "/repos/example/example/branches/\u{130}/protection",
            long.as_str(),
        ] {
            for body in bodies {
                let _ = protection_write(method, path, body);
            }
        }
    }
    assert!(protection_write("PUT", "/repos/example/example/rulesets", b"").is_some());
    assert!(protection_write("GET", "/repos/example/example/rulesets", b"").is_none());
}

/// Brief: the guard never panics on any input. Boundary argument lists for `gh api`, a
/// flag with no value at the end among them, each judged without a panic.
#[test]
fn gh_api_refusal_never_panics_on_boundary_arguments() {
    let unreadable = |_: &str| -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::from(std::io::ErrorKind::NotFound))
    };
    let cases: [&[&str]; 16] = [
        &["api"],
        &["api", ""],
        &["api", "--input"],
        &["api", "-F"],
        &["api", "--field"],
        &["api", "-F", ""],
        &["api", "="],
        &["api", "-"],
        &["api", "-=", "@"],
        &["api", "{owner}"],
        &["api", "://{owner}"],
        &["api", "{owner}://"],
        &["api", "\u{130}{owner}/x/{repo}"],
        &["api", "-\u{e9}F", "k=@f"],
        &["api", "{owner}/{repo}/{owner}/{repo}/{owner}"],
        &["api", "%", "%%", "%2"],
    ];
    for args in cases {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        let _ = gh_api_refusal(&args, unreadable);
    }
    let protected: Vec<String> = ["api", "-X", "PUT", "repos/example/example/rulesets/1"]
        .iter()
        .map(|a| (*a).to_owned())
        .collect();
    assert!(gh_api_refusal(&protected, unreadable).is_some());
}
