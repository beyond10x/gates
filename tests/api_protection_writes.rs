//! `story:api-protection-writes`, modelled as `gates.delivery.BotApi` in
//! `ess/domains/delivery.yaml`: `b10x-gates api` and `b10x-gates gh -- api` refuse a write
//! to a ruleset or to branch protection before a token is minted.
//!
//! Every run here has no bot configuration (`B10X_BOT_CONFIG` names an absent file) and,
//! unless a case supplies one, no policy, and `PATH` names an empty directory, so no `gh`
//! can run and nothing reaches GitHub. A refusal that names neither the absent bot
//! configuration nor `policy.json` came before the token step and before the policy was
//! read; an error naming the absent bot configuration reached the token step.
#[path = "support/formats.rs"]
mod formats;

use b10x_gates::policy::Policy;
use formats::{
    CPU_X86_64, DEFLATED, MH_EXECUTE, S_IFCHR, S_IFIFO, S_IFLNK, Zip, ZipEntry, macho_fat, macho64,
    macho64_with, pe,
};
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

struct Run {
    ok: bool,
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

    /// A synthetic policy, owner-only, so a case that is not refused passes the
    /// private-rule scan and reaches the token step.
    fn with_policy(self) -> Self {
        self.with_literals(&[&["synthetic", "restricted", "identifier"].join("-")])
    }

    /// As `with_policy`, with these literals as the private rules.
    fn with_literals(mut self, literals: &[&str]) -> Self {
        let path = self.dir.path().join("policy.json");
        let policy = Policy {
            version: 1,
            nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
            forbidden_literals: literals.iter().map(|v| v.to_string()).collect(),
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

    fn command(&self) -> Command {
        let config = self.path().join("config");
        let mut command = Command::new(env!("CARGO_BIN_EXE_b10x-gates"));
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
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        }
    }

    fn api(&self, method: &str, path: &str, input: Option<&[u8]>) -> Run {
        let mut command = self.command();
        command
            .args(["api", "--method", method, "--path", path, "--output"])
            .arg(self.path().join("response.json"));
        if let Some(bytes) = input {
            command.arg("--input").arg(self.file("request.json", bytes));
        }
        self.run(command)
    }

    fn gh(&self, args: &[&str]) -> Run {
        let mut command = self.command();
        command
            .arg("--repo")
            .arg(self.path())
            .args(["gh", "--", "api"])
            .args(args);
        self.run(command)
    }

    /// `gh` as above under a 60 s `timeout`, with the time the run took.
    fn gh_timed(&self, args: &[&str]) -> (Run, Duration) {
        let inner = self.command();
        let mut command = Command::new("/usr/bin/timeout");
        command
            .arg("60")
            .arg(inner.get_program())
            .current_dir(self.path());
        for (key, value) in inner.get_envs() {
            match value {
                Some(value) => command.env(key, value),
                None => command.env_remove(key),
            };
        }
        command
            .arg("--repo")
            .arg(self.path())
            .args(["gh", "--", "api"])
            .args(args);
        let started = Instant::now();
        let run = self.run(command);
        (run, started.elapsed())
    }
}

/// Refused by the guard, naming `named`, before the policy is read and before the token
/// step.
fn refused(run: &Run, named: &str) {
    assert!(!run.ok, "{}", run.stderr);
    assert!(run.stderr.contains(OWNERS), "{}", run.stderr);
    assert!(run.stderr.contains(named), "{named}: {}", run.stderr);
    assert!(!run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
    assert!(!run.stderr.contains("policy.json"), "{}", run.stderr);
}

/// Not refused by the guard: the run went on to the token step.
fn reached_token(run: &Run) {
    assert!(!run.ok, "{}", run.stderr);
    assert!(!run.stderr.contains(OWNERS), "{}", run.stderr);
    assert!(run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
}

/// The refusal shows the path escaped for the terminal (`\t`, `\\`).
fn write_refused(method: &str, path: &str) {
    refused(
        &Sandbox::new().api(method, path, None),
        &path.escape_debug().to_string(),
    );
}

fn read_reaches_token(method: &str, path: &str) {
    reached_token(&Sandbox::new().api(method, path, None));
}

/// Each REST family: every write method is refused, GET and HEAD are not.
macro_rules! family {
    ($($family:ident => $path:literal),* $(,)?) => {$(
        mod $family {
            #[test]
            fn put_is_refused() {
                super::write_refused("PUT", $path);
            }
            #[test]
            fn patch_is_refused() {
                super::write_refused("PATCH", $path);
            }
            #[test]
            fn post_is_refused() {
                super::write_refused("POST", $path);
            }
            #[test]
            fn delete_is_refused() {
                super::write_refused("DELETE", $path);
            }
            #[test]
            fn get_reaches_the_token_step() {
                super::read_reaches_token("GET", $path);
            }
            #[test]
            fn head_reaches_the_token_step() {
                super::read_reaches_token("HEAD", $path);
            }
        }
    )*};
}

family! {
    repository_rulesets => "/repos/example/example/rulesets",
    repository_ruleset => "/repos/example/example/rulesets/42",
    branch_protection => "/repos/example/example/branches/main/protection",
    slashed_branch_protection_below =>
        "/repos/example/example/branches/release/v1/protection/required_status_checks/contexts",
    organization_rulesets => "/orgs/example/rulesets",
    organization_ruleset => "/orgs/example/rulesets/42",
    repository_id_rulesets => "/repositories/1/rulesets/42",
    repository_id_branch_protection => "/repositories/1/branches/main/protection/enforce_admins",
}

#[test]
fn method_is_compared_case_insensitively() {
    write_refused("put", "/repos/example/example/rulesets/42");
    write_refused("Delete", "/repos/example/example/branches/main/protection");
    read_reaches_token("get", "/repos/example/example/rulesets/42");
}

/// Each normalisation GitHub (or the URL parser on the way) applies is undone before the
/// path is judged.
macro_rules! normalised {
    ($($case:ident => $path:expr),* $(,)?) => {$(
        #[test]
        fn $case() {
            write_refused("PUT", $path);
        }
    )*};
}

normalised! {
    normalised_case => "/REPOS/Example/Example/RuleSets/42",
    normalised_percent_encoding => "/repos/example/example/%72ulesets/42",
    normalised_repeated_percent_encoding => "/repos/example/example/%25%37%32ulesets",
    normalised_encoded_separator => "/repos/example/example%2Frulesets",
    normalised_repeated_slashes => "/repos//example/example//branches//main//protection",
    normalised_trailing_slash => "/repos/example/example/rulesets/",
    normalised_query_string => "/repos/example/example/rulesets?per_page=1",
    normalised_encoded_query_string => "/repos/example/example/rulesets%3Fper_page=1",
    normalised_repository_id_alias => "/REPOSITORIES/1//Rulesets/",
    normalised_dot_segment => "/repos/example/example/%2e/rulesets",
    normalised_parent_segment => "/repos/example/example/x/%2E%2E/rulesets",
    normalised_parent_after_encoded_query => "/x%3F/%2e%2e/repos/example/example/rulesets",
    normalised_backslash => "/repos/example/example\\rulesets",
    normalised_tab => "/repos/example/example/rule\tsets",
    normalised_format_suffix => "/repos/example/example/rulesets.json",
    normalised_branch_named_protection => "/repos/example/example/branches/protection/protection",
    normalised_padded_segment => "/repos/example/example/%20rulesets",
    normalised_parent_segments_read_unresolved => "/repos/example/example/rulesets/../..",
}

#[test]
fn undecodable_write_path_is_refused() {
    for path in [
        "/repos/example/example/%zz",
        "/repos/example/example/%4",
        "/repos/example/example/%ff",
    ] {
        let run = Sandbox::new().api("POST", path, None);
        refused(&run, path);
        assert!(run.stderr.contains("cannot be decoded"), "{}", run.stderr);
    }
}

/// Round 2, A4: only the first decoding is strict. A `%` that the first decoding yields
/// (a label named `50%`, spelled `50%25`) is text, not an escape that fails.
#[test]
fn writes_elsewhere_reach_the_token_step() {
    for path in [
        "/repos/example/example/issues",
        "/repos/example/example/contents/rulesets/protection",
        "/repos/example/example/branches/protection/rename",
        "/repos/rulesets/protection/pulls",
        "/orgs/example/teams",
        "/repos/example/example/labels/50%25",
        "/repos/example/example/labels/%25zz",
        "/repos/example/example/labels/%25ff",
    ] {
        reached_token(&Sandbox::new().api("POST", path, None));
    }
}

fn mutation(name: &str) -> Vec<u8> {
    serde_json::json!({
        "query": format!("mutation {{ {name}(input: {{}}) {{ clientMutationId }} }}"),
    })
    .to_string()
    .into_bytes()
}

macro_rules! mutations {
    ($($case:ident => $name:literal),* $(,)?) => {$(
        #[test]
        fn $case() {
            let run = Sandbox::new().api("POST", "/graphql", Some(&super::mutation($name)));
            super::refused(&run, $name);
        }
    )*};
}

mod graphql {
    use super::Sandbox;

    mutations! {
        create_repository_ruleset_is_refused => "createRepositoryRuleset",
        update_repository_ruleset_is_refused => "updateRepositoryRuleset",
        delete_repository_ruleset_is_refused => "deleteRepositoryRuleset",
        create_branch_protection_rule_is_refused => "createBranchProtectionRule",
        update_branch_protection_rule_is_refused => "updateBranchProtectionRule",
        delete_branch_protection_rule_is_refused => "deleteBranchProtectionRule",
    }
}

/// `mutation(name)` with the letter at `at` of the name written as the JSON escape
/// `\u00XX`. The backslash is `char::from(92)` and the escape is built here, at run time:
/// a file-writing tool once decoded a literal escape in this source to the plain letter,
/// and the test then held no escape at all.
fn escaped_mutation(name: &str, at: usize) -> Vec<u8> {
    let letter = name[at..].chars().next().unwrap();
    let escape = format!("{}u{:04x}", char::from(92u8), u32::from(letter));
    let spelled = format!("{}{escape}{}", &name[..at], &name[at + letter.len_utf8()..]);
    let body = String::from_utf8(mutation(name))
        .unwrap()
        .replacen(name, &spelled, 1);
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert!(
        parsed["query"].as_str().unwrap().contains(name),
        "fixture: the escape decodes to {name}"
    );
    assert!(!body.contains(name), "fixture: the raw body hides {name}");
    body.into_bytes()
}

#[test]
fn graphql_mutation_behind_a_json_escape_is_refused() {
    let body = escaped_mutation("updateRepositoryRuleset", 3);
    refused(
        &Sandbox::new().api("POST", "/graphql", Some(&body)),
        "updateRepositoryRuleset",
    );
}

#[test]
fn graphql_path_is_normalised() {
    for path in ["/GraphQL/", "//graphql?x=1", "/%67raphql"] {
        refused(
            &Sandbox::new().api("POST", path, Some(&mutation("deleteBranchProtectionRule"))),
            "deleteBranchProtectionRule",
        );
    }
}

/// A `/graphql` path's query string is read as well as the body, in every reading.
#[test]
fn graphql_mutation_in_the_query_string_is_refused() {
    for (method, path, name) in [
        (
            "GET",
            "/graphql?query=mutation%20%7B%20deleteRepositoryRuleset(input%3A%20%7B%7D)%20%7B%20clientMutationId%20%7D%20%7D",
            "deleteRepositoryRuleset",
        ),
        (
            "POST",
            "/graphql?query=mutation{createBranchProtectionRule(input:{}){clientMutationId}}",
            "createBranchProtectionRule",
        ),
        (
            "GET",
            "/GraphQL/?query=mutation+%7B+update%2552epositoryRuleset+%7D",
            "updateRepositoryRuleset",
        ),
    ] {
        refused(&Sandbox::new().api(method, path, None), name);
    }
}

#[test]
fn graphql_query_string_naming_no_mutation_reaches_the_token_step() {
    reached_token(&Sandbox::new().api(
        "GET",
        "/graphql?query=query%20%7B%20viewer%20%7B%20login%20%7D%20%7D",
        None,
    ));
}

#[test]
fn graphql_mutation_is_refused_whatever_the_method() {
    refused(
        &Sandbox::new().api(
            "GET",
            "/graphql",
            Some(&mutation("createRepositoryRuleset")),
        ),
        "createRepositoryRuleset",
    );
}

#[test]
fn graphql_query_naming_no_mutation_reaches_the_token_step() {
    let body = serde_json::json!({
        "query": "query { repository(owner: \"example\", name: \"example\") { \
                  rulesets(first: 1) { nodes { id } } \
                  branchProtectionRules(first: 1) { nodes { pattern } } } }",
    })
    .to_string();
    reached_token(
        &Sandbox::new()
            .with_policy()
            .api("POST", "/graphql", Some(body.as_bytes())),
    );
}

#[test]
fn gh_api_inline_path_is_refused_whatever_the_method() {
    for args in [
        &["--method", "PUT", "repos/{owner}/{repo}/rulesets/42"][..],
        &["repos/{owner}/{repo}/rulesets"],
        &["--method", "GET", "repos/example/example/rulesets"],
        &[
            "-X",
            "DELETE",
            "/repos/example/example/branches/main/protection",
        ],
        &["https://api.github.com/orgs/example/rulesets"],
        &["--method=PATCH", "REPOS/example/example/%72ulesets/42"],
        &["repositories/1/branches/main/protection/enforce_admins"],
    ] {
        let run = Sandbox::new().gh(args);
        refused(&run, "argument");
        assert!(
            run.stderr.contains("rulesets") || run.stderr.contains("protection"),
            "{}",
            run.stderr
        );
    }
}

#[test]
fn gh_api_inline_mutation_is_refused() {
    for args in [
        &[
            "graphql",
            "-f",
            "query=mutation { createBranchProtectionRule(input: {}) { clientMutationId } }",
        ][..],
        &[
            "graphql",
            "--raw-field",
            "query=mutation { deleteRepositoryRuleset(input: {}) { clientMutationId } }",
        ],
    ] {
        let run = Sandbox::new().gh(args);
        refused(&run, "argument");
        assert!(
            run.stderr.contains("createBranchProtectionRule")
                || run.stderr.contains("deleteRepositoryRuleset"),
            "{}",
            run.stderr
        );
    }
}

#[test]
fn gh_api_input_file_naming_a_mutation_is_refused() {
    for form in ["separate", "joined"] {
        let sandbox = Sandbox::new();
        sandbox.file("request.json", &mutation("updateBranchProtectionRule"));
        let run = match form {
            "separate" => sandbox.gh(&["graphql", "--input", "request.json"]),
            _ => sandbox.gh(&["graphql", "--input=request.json"]),
        };
        refused(&run, "updateBranchProtectionRule");
        assert!(run.stderr.contains("the file it names"), "{}", run.stderr);
    }
}

#[test]
fn gh_api_input_file_naming_a_protected_path_is_refused() {
    let sandbox = Sandbox::new();
    sandbox.file(
        "request.json",
        br#"{"url":"https:\/\/api.github.com\/repos\/example\/example\/rulesets\/42"}"#,
    );
    let run = sandbox.gh(&["repos/example/example/issues", "--input", "request.json"]);
    refused(&run, "rulesets");
    assert!(run.stderr.contains("the file it names"), "{}", run.stderr);
}

#[test]
fn gh_api_field_file_naming_a_mutation_is_refused() {
    for args in [
        &["graphql", "-F", "query=@query.graphql"][..],
        &["graphql", "--field", "query=@query.graphql"],
        &["graphql", "--field=query=@query.graphql"],
        &["graphql", "-Fquery=@query.graphql"],
        &["graphql", "-F=query=@query.graphql"],
        &["graphql", "-iF", "query=@query.graphql"],
    ] {
        let sandbox = Sandbox::new();
        sandbox.file(
            "query.graphql",
            b"mutation { createRepositoryRuleset(input: {}) { clientMutationId } }",
        );
        let run = sandbox.gh(args);
        refused(&run, "createRepositoryRuleset");
        assert!(run.stderr.contains("the file it names"), "{}", run.stderr);
    }
}

#[test]
fn gh_api_standard_input_is_refused() {
    for args in [
        &["graphql", "--input", "-"][..],
        &["graphql", "--input=-"],
        &["graphql", "-F", "query=@-"],
    ] {
        let run = Sandbox::new().gh(args);
        refused(&run, "standard input");
    }
}

#[test]
fn gh_api_unreadable_field_file_is_refused() {
    let run = Sandbox::new().gh(&["graphql", "-F", "query=@absent.graphql"]);
    assert!(!run.ok, "{}", run.stderr);
    assert!(run.stderr.contains("absent.graphql"), "{}", run.stderr);
    assert!(run.stderr.contains("cannot be read"), "{}", run.stderr);
    assert!(!run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
    assert!(!run.stderr.contains("policy.json"), "{}", run.stderr);
}

#[test]
fn gh_api_elsewhere_reaches_the_token_step() {
    let sandbox = Sandbox::new().with_policy();
    sandbox.file("query.graphql", b"query { viewer { login } }");
    reached_token(&sandbox.gh(&["graphql", "-F", "query=@query.graphql"]));
    reached_token(&sandbox.gh(&[
        "repos/example/example/issues",
        "-f",
        "title=example",
        "-f",
        "body=@example please review",
    ]));
}

/// `gh` fills `{branch}` with the current branch name after the guard has read the
/// argument, and a branch name may hold `/`: on a branch named `main/protection`,
/// `branches/{branch}` is a branch protection path.
#[test]
fn gh_api_branch_placeholder_in_a_path_is_refused() {
    for args in [
        &["--method", "PUT", "repos/{owner}/{repo}/branches/{branch}"][..],
        &["-X", "PUT", "repos/:owner/:repo/branches/:branch"],
        &["--method", "POST", "{branch}"],
    ] {
        let run = Sandbox::new().gh(args);
        refused(&run, "branch");
    }
}

/// An owner or name placeholder fills one whole segment, which may be any word.
#[test]
fn gh_api_owner_or_repo_placeholder_is_judged_as_any_segment() {
    for args in [
        &["--method", "POST", "repos/{owner}/example/{repo}"][..],
        &["--method", "POST", "orgs/example/{repo}"],
        &[
            "--method",
            "PUT",
            "https://api.github.com/repos/example/{owner}/{repo}",
        ],
    ] {
        let run = Sandbox::new().gh(args);
        refused(&run, "placeholder");
    }
}

/// A placeholder `gh` fills into the GraphQL query may complete a mutation name.
#[test]
fn gh_api_placeholder_in_a_graphql_query_is_refused() {
    let run = Sandbox::new().gh(&[
        "graphql",
        "-F",
        "query=mutation { delete{repo}(input: {rulesetId: \"x\"}) { clientMutationId } }",
    ]);
    refused(&run, "query");
}

#[test]
fn gh_api_placeholders_elsewhere_reach_the_token_step() {
    let sandbox = Sandbox::new().with_policy();
    reached_token(&sandbox.gh(&[
        "--method",
        "POST",
        "repos/{owner}/{repo}/pulls",
        "-F",
        "head={branch}",
        "--field=base={branch}",
        "-F",
        "owner={owner}",
        "-f",
        "title=example",
    ]));
    reached_token(&sandbox.gh(&["repos/{owner}/{repo}/commits/main/status"]));
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

/// GitHub decodes a body sent with `Content-Encoding` (or `Transfer-Encoding`) before it
/// reads it, so the bytes the guard read are not the request: refused in every spelling
/// of `-H`/`--header` and any letter case.
#[test]
fn gh_api_body_encoding_header_is_refused() {
    let compressed = gzip(&mutation("deleteBranchProtectionRule"));
    assert!(
        !String::from_utf8_lossy(&compressed)
            .to_lowercase()
            .contains("deletebranchprotectionrule"),
        "fixture: the compressed body hides the mutation name"
    );
    for header in [
        &["-H", "Content-Encoding: gzip"][..],
        &["-Hcontent-encoding:gzip"],
        &["-H=CONTENT-ENCODING: gzip"],
        &["--header", "Content-Encoding : gzip"],
        &["--header=Content-Encoding:gzip"],
        &["-iH", "Content-Encoding: gzip"],
        &["-iHContent-Encoding:gzip"],
        &["-H", "Transfer-Encoding: gzip"],
    ] {
        let sandbox = Sandbox::new();
        sandbox.file("request.json", &compressed);
        let mut args = vec!["graphql", "--input", "request.json"];
        args.extend_from_slice(header);
        let run = sandbox.gh(&args);
        refused(&run, "Encoding");
        assert!(run.stderr.contains("argument"), "{}", run.stderr);
    }
}

/// A body in UTF-16 or UTF-32 hides a mutation name from a reading of its bytes as UTF-8;
/// the guard reads those encodings too.
#[test]
fn gh_api_input_file_in_utf16_or_utf32_is_read_decoded() {
    let name = "deleteBranchProtectionRule";
    let text = String::from_utf8(mutation(name)).unwrap();
    let encodings: [Vec<u8>; 4] = [
        text.encode_utf16().flat_map(u16::to_le_bytes).collect(),
        text.encode_utf16().flat_map(u16::to_be_bytes).collect(),
        text.chars()
            .flat_map(|c| u32::from(c).to_le_bytes())
            .collect(),
        text.chars()
            .flat_map(|c| u32::from(c).to_be_bytes())
            .collect(),
    ];
    for bytes in encodings {
        assert!(
            !String::from_utf8_lossy(&bytes).contains(name),
            "fixture: the encoded body hides {name}"
        );
        let sandbox = Sandbox::new();
        sandbox.file("request.json", &bytes);
        refused(&sandbox.gh(&["graphql", "--input", "request.json"]), name);
    }
}

/// The escape reaches the guard through `gh` too: an `--input` file whose mutation name
/// holds a JSON `\u` escape.
#[test]
fn gh_api_input_file_with_a_json_escape_is_refused() {
    let sandbox = Sandbox::new();
    sandbox.file(
        "request.json",
        &escaped_mutation("createRepositoryRuleset", 0),
    );
    refused(
        &sandbox.gh(&["graphql", "--input", "request.json"]),
        "createRepositoryRuleset",
    );
}

/// The backslash of a JSON escape, built at run time so no tool can decode it.
fn backslash() -> char {
    char::from(92u8)
}

/// Round 2, A1: a mutation name counts only as a whole GraphQL name, so a read naming an
/// input or payload type of the same stem stays open.
#[test]
fn graphql_type_named_after_a_mutation_reaches_the_token_step() {
    let body = serde_json::json!({
        "query": "query { __type(name: \"UpdateBranchProtectionRuleInput\") { name } \
                  payload: __type(name: \"deleteRepositoryRuleset_payload\") { name } }",
    })
    .to_string();
    reached_token(
        &Sandbox::new()
            .with_policy()
            .api("POST", "/graphql", Some(body.as_bytes())),
    );
    reached_token(&Sandbox::new().with_policy().gh(&[
        "graphql",
        "-f",
        "query=query{__type(name:\"CreateRepositoryRulesetPayload\"){name}}",
    ]));
}

/// Round 2, A1: a whole name is still found in any letter case and after a JSON escape
/// such as the newline that usually precedes it in a multi-line query.
#[test]
fn graphql_whole_mutation_name_after_a_json_newline_or_in_upper_case_is_refused() {
    let newline = format!("{}n", backslash());
    let body = format!(
        "{{\"query\":\"mutation {{{newline}updateRepositoryRuleset(input: {{}}) {{ clientMutationId }} }}\"}}"
    );
    assert!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["query"]
            .as_str()
            .unwrap()
            .contains("\nupdateRepositoryRuleset"),
        "fixture: the escape decodes to a newline before the name"
    );
    refused(
        &Sandbox::new().api("POST", "/graphql", Some(body.as_bytes())),
        "updateRepositoryRuleset",
    );
    refused(
        &Sandbox::new().api(
            "POST",
            "/graphql",
            Some(br#"{"query":"MUTATION { DELETEREPOSITORYRULESET(input: {}) { x } }"}"#),
        ),
        "deleteRepositoryRuleset",
    );
}

/// Round 2, A2: a placeholder is refused as part of a GraphQL query only in an argument
/// that sets the `query` field, in every spelling of a field argument.
#[test]
fn gh_api_placeholder_in_the_query_field_is_refused_in_every_spelling() {
    let query = "query=mutation { delete{repo}(input: {rulesetId: \"x\"}) { clientMutationId } }";
    let upper = query.replacen("query=", "QUERY=", 1);
    let joined = [
        format!("-F{query}"),
        format!("-f{query}"),
        format!("-F={query}"),
        format!("-iF{query}"),
        format!("--field={query}"),
        format!("--raw-field={query}"),
    ];
    let mut cases: Vec<Vec<&str>> = vec![
        vec!["graphql", "-F", query],
        vec!["graphql", "--raw-field", query],
        vec!["graphql", "-F", upper.as_str()],
    ];
    cases.extend(joined.iter().map(|a| vec!["graphql", a.as_str()]));
    for args in cases {
        let run = Sandbox::new().gh(&args);
        refused(&run, "query");
    }
}

/// Round 2, A2: an argument that only mentions `query` sets no GraphQL query.
#[test]
fn gh_api_placeholder_beside_the_word_query_elsewhere_reaches_the_token_step() {
    let sandbox = Sandbox::new().with_policy();
    reached_token(&sandbox.gh(&["repos/{owner}/{repo}/contents/docs/query.md"]));
    reached_token(&sandbox.gh(&[
        "repos/{owner}/{repo}/issues",
        "-f",
        "title=the query for {repo}",
    ]));
}

/// Round 2, A5: a refusal names a protection path found in text only up to its `rulesets`
/// segment and a numeric ruleset id, or up to its `protection` segment; text after that,
/// after a `\`, or after the fixed word in the same segment is never shown.
#[test]
fn refusal_names_a_found_path_only_up_to_its_protection_segment() {
    let marker = "private-marker-text";
    let slash = backslash();
    for (body, named) in [
        (
            format!("see repos/example/example/rulesets/42/{marker}"),
            "/repos/example/example/rulesets/42",
        ),
        (
            format!("see repos/example/example/rulesets/{marker}"),
            "/repos/example/example/rulesets",
        ),
        (
            format!("see repos/example/example/branches/main/protection/enforce_admins/{marker}"),
            "/repos/example/example/branches/main/protection",
        ),
        (
            format!("see repos/example/example/rulesets{slash}{marker}"),
            "/repos/example/example/rulesets",
        ),
        (
            format!("see orgs/example/rulesets.{marker}"),
            "/orgs/example/rulesets",
        ),
    ] {
        let sandbox = Sandbox::new();
        sandbox.file("body.txt", body.as_bytes());
        let run = sandbox.gh(&["repos/example/example/issues", "--input", "body.txt"]);
        refused(&run, named);
        assert!(!run.stderr.contains(marker), "{}", run.stderr);
    }
    let run = Sandbox::new().gh(&["-X", "PUT", &format!("repos/{{owner}}/x/{{repo}}/{marker}")]);
    refused(&run, "/repos/x/x/rulesets");
    assert!(!run.stderr.contains(marker), "{}", run.stderr);
}

/// Round 2 follow-up: a path found in text runs on past a `\`, which every reading takes
/// as a separator, so a path spelled with `\` in a file or an argument is still found.
/// The refusal shows it only up to its protection segment.
#[test]
fn gh_api_backslash_separated_path_is_refused() {
    let slash = backslash();
    let spelled = format!("repos{slash}example{slash}example{slash}rulesets");
    let sandbox = Sandbox::new();
    sandbox.file("body.txt", format!("see {spelled} there").as_bytes());
    refused(
        &sandbox.gh(&["repos/example/example/issues", "--input", "body.txt"]),
        "/repos/example/example/rulesets",
    );
    refused(
        &Sandbox::new().gh(&["-X", "PUT", &spelled]),
        "/repos/example/example/rulesets",
    );
}

/// Round 2, A6: every argument and named file is read for a protection path or a mutation
/// before an encoding header is refused, so the refusal names what the request changes.
#[test]
fn gh_api_mutation_in_a_file_is_named_before_an_encoding_header() {
    let sandbox = Sandbox::new();
    sandbox.file("request.json", &mutation("deleteBranchProtectionRule"));
    let run = sandbox.gh(&[
        "graphql",
        "-H",
        "Content-Encoding: identity",
        "--input",
        "request.json",
    ]);
    refused(&run, "deleteBranchProtectionRule");
    assert!(!run.stderr.contains("Content-Encoding"), "{}", run.stderr);
}

/// `%` then `25` `depth` times then `41`: one more decoding than `depth` yields `A`.
fn nested_percent(depth: usize) -> String {
    format!("%{}41", "25".repeat(depth))
}

/// Round 2, A7: at most 8 decodings. Text still changing after the 8th is refused as
/// undecodable, in a path, a body and a named file; text that settles within 8 is read.
#[test]
fn text_still_changing_after_eight_decodings_is_refused() {
    let issue = "/repos/example/example/issues/1/";
    reached_token(&Sandbox::new().api("PATCH", &format!("{issue}{}", nested_percent(7)), None));
    let path = format!("{issue}{}", nested_percent(8));
    let run = Sandbox::new().api("PATCH", &path, None);
    refused(&run, &path);
    assert!(run.stderr.contains("cannot be decoded"), "{}", run.stderr);
    // A protection path that settles at the 8th decoding is read and refused.
    let hidden = format!("/repos/example/example/%{}72ulesets", "25".repeat(7));
    let run = Sandbox::new().api("PUT", &hidden, None);
    refused(&run, &hidden);
    assert!(!run.stderr.contains("cannot be decoded"), "{}", run.stderr);
    // A `/graphql` body.
    let run = Sandbox::new().api("POST", "/graphql", Some(nested_percent(8).as_bytes()));
    refused(&run, "cannot be decoded");
    // A named file through `gh`.
    for (depth, refusal) in [(7, false), (8, true)] {
        let sandbox = Sandbox::new().with_policy();
        sandbox.file("body.json", nested_percent(depth).as_bytes());
        let run = sandbox.gh(&["repos/example/example/issues", "--input", "body.json"]);
        if refusal {
            refused(&run, "cannot be decoded");
        } else {
            reached_token(&run);
        }
    }
}

/// Round 3, B1: the most a text of `repos/` with no separator may take to be judged, debug
/// build, with every place a path may begin six bytes after the last.
const QUICK: Duration = Duration::from_secs(5);

fn judged_quickly(took: Duration, run: &Run) {
    let stderr: String = run.stderr.chars().take(300).collect();
    assert!(
        took < QUICK,
        "judged in {took:?}, bound {QUICK:?}; stderr: {stderr}"
    );
}

/// Round 3, B1: one argument as long as Linux allows (`MAX_ARG_STRLEN`, 128 KiB with its
/// NUL) of `repos/` repeated carries no protection path and is admitted, in linear time.
#[test]
fn longest_argument_of_repeated_repos_segments_is_judged_quickly() {
    let argument = "repos/".repeat((128 * 1024 - 1) / 6);
    let sandbox = Sandbox::new().with_policy();
    let (run, took) = sandbox.gh_timed(&["repos/example/example/issues", &argument]);
    judged_quickly(took, &run);
    reached_token(&run);
}

/// Round 3, B1: a 1 MiB `--input` file of `repos/` repeated is admitted, in linear time.
#[test]
fn mebibyte_input_file_of_repeated_repos_segments_is_judged_quickly() {
    let sandbox = Sandbox::new().with_policy();
    sandbox.file("body.json", "repos/".repeat(1024 * 1024 / 6).as_bytes());
    let (run, took) = sandbox.gh_timed(&["repos/example/example/issues", "--input", "body.json"]);
    judged_quickly(took, &run);
    reached_token(&run);
}

/// Round 3, B1: a protection path at the end of the same 1 MiB text is still found.
#[test]
fn protection_path_after_a_mebibyte_of_repeated_repos_segments_is_refused_quickly() {
    let sandbox = Sandbox::new();
    let mut body = "repos/".repeat(1024 * 1024 / 6);
    body.push_str("example/example/branches/main/protection");
    sandbox.file("body.json", body.as_bytes());
    let (run, took) = sandbox.gh_timed(&["repos/example/example/issues", "--input", "body.json"]);
    judged_quickly(took, &run);
    refused(&run, "/repos/example/example/branches/main/protection");
}

/// Round 3, B1, the same class: `gh` placeholders are judged by trying every stand-in in
/// every segment that holds one, each filling read whole. More text than that work allows
/// is refused as not judged, quickly, rather than judged for minutes.
#[test]
fn placeholders_in_more_text_than_can_be_judged_are_refused_quickly() {
    let argument = format!(
        "a/b/{{owner}}/{{repo}}/{{owner}}/{{repo}}/{}",
        "a".repeat(128 * 1024 - 64)
    );
    let (run, took) = Sandbox::new().gh_timed(&["-X", "PUT", &argument]);
    judged_quickly(took, &run);
    refused(&run, "placeholder");
}

// `gh -- run download --dir <path>`: the directory `gh` writes the artifact to is a local
// path and is sent nowhere, so `personal-paths` does not refuse it. Every other rule still
// does, every other argument is still scanned, and no other command is admitted.

/// A synthetic home directory the `personal-paths` rule matches.
fn home() -> String {
    ["", "home", "fixture-person"].join("/")
}

fn literal() -> String {
    ["synthetic", "restricted", "identifier"].join("-")
}

/// `b10x-gates gh -- <args>` under the synthetic policy.
fn gh_scanned(args: &[&str]) -> Run {
    gh_in(&Sandbox::new().with_policy(), args)
}

/// `b10x-gates gh -- <args>` in `sandbox`, with the sandbox as `--repo`.
fn gh_in(sandbox: &Sandbox, args: &[&str]) -> Run {
    let mut command = sandbox.command();
    command
        .arg("--repo")
        .arg(sandbox.path())
        .args(["gh", "--"])
        .args(args);
    sandbox.run(command)
}

/// Passed the argument scan: the run went on to the token step.
fn scan_passed(run: &Run) {
    assert!(!run.stderr.contains("private rule"), "{}", run.stderr);
    reached_token(run);
}

/// Refused by the argument scan, on `argument` (1-based), for exactly `rules`, before the
/// token step.
fn scan_refused(run: &Run, argument: usize, rules: &[&str]) {
    let named = format!(
        "argument {argument} breaks {} private rule(s): {};",
        rules.len(),
        rules
            .iter()
            .map(|rule| format!("line 1 {rule}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(!run.ok, "{}", run.stderr);
    assert!(run.stderr.contains(&named), "{named}: {}", run.stderr);
    assert!(!run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
}

#[test]
fn run_download_dir_under_the_home_directory_passes_the_scan() {
    let dir = format!("{}/downloads", home());
    let joined = format!("--dir={dir}");
    for args in [
        &["run", "download", "1", "--repo", "o/r", "--dir", &dir][..],
        &["run", "download", "1", "--repo", "o/r", "-D", &dir],
        &["run", "download", "1", "--repo", "o/r", &joined],
        &["run", "download", "--dir", &dir, "1", "--name", "a"],
        &[
            "run", "download", "-n", "a", "-p", "b-*", "-R", "o/r", "-D", &dir, "1",
        ],
    ] {
        scan_passed(&gh_scanned(args));
    }
}

#[test]
fn dir_under_the_home_directory_is_refused_for_every_other_command() {
    let dir = format!("{}/downloads", home());
    for (args, argument) in [
        (&["pr", "create", "--dir", &dir][..], 4),
        (&["issue", "create", "--dir", &dir], 4),
        (&["api", "repos/o/r/issues", "--dir", &dir], 4),
        (&["release", "create", "v1", "--dir", &dir], 5),
        (&["run", "view", "1", "--dir", &dir], 5),
        (&["run", "view", "-D", &dir], 4),
        (&["workflow", "run", "download", "--dir", &dir], 5),
        (&["download", "run", "--dir", &dir], 4),
        (&["run", "--dir", &dir, "download"], 3),
        (&["-R", "o/r", "run", "download", "--dir", &dir], 6),
    ] {
        scan_refused(&gh_scanned(args), argument, &["personal-paths"]);
    }
}

#[test]
fn run_download_other_arguments_are_still_scanned() {
    let path = format!("{}/x", home());
    let name = format!("--name={path}");
    for (args, argument) in [
        (&["run", "download", &path, "--dir", "out"][..], 3),
        (&["run", "download", "1", "--name", &path], 5),
        (&["run", "download", "1", "-n", &path], 5),
        (&["run", "download", "1", &name], 4),
        (&["run", "download", "1", "--pattern", &path], 5),
        (&["run", "download", "1", "-p", &path], 5),
        (&["run", "download", "1", "--repo", &path], 5),
        (&["run", "download", "1", "-R", &path], 5),
        // `--dir` here is the value of `--name`; the path after it is the run id.
        (&["run", "download", "--name", "--dir", &path], 5),
        (&["run", "download", "-n", "-D", &path], 5),
        (&["run", "download", "--name=--dir", &path], 4),
        // After `--` every word is positional.
        (&["run", "download", "1", "--", "--dir", &path], 6),
    ] {
        scan_refused(&gh_scanned(args), argument, &["personal-paths"]);
    }
}

#[test]
fn run_download_dir_is_still_refused_for_every_other_rule() {
    let literal = literal();
    let both = format!("{}/{literal}", home());
    let joined = format!("--dir={both}");
    for (args, argument) in [
        (&["run", "download", "1", "--dir", &literal][..], 5),
        (&["run", "download", "1", "-D", &both], 5),
        (&["run", "download", "1", "--dir", &both], 5),
        (&["run", "download", "1", &joined], 4),
    ] {
        scan_refused(&gh_scanned(args), argument, &["private-identifiers"]);
    }
}

// Security review of the `run download` admission: a word is admitted only where `gh`
// (cobra and pflag) reads it as the download directory. pflag gives a valued option the next
// word whatever it starts with, `-x=v` and `-xv` attach a value, and `--` ends the options.

#[test]
fn run_download_admits_no_word_gh_reads_as_anything_but_the_directory() {
    let home = home();
    let attached = ["-n=--dir", "-n--dir", "--repo=-D", "-RD", "-p=-D"];
    let mut cases: Vec<(Vec<&str>, usize)> = vec![
        // The word after `--dir` is its value even when it is an option; the home path
        // after it is then the run id `gh` puts in the request URL.
        (vec!["run", "download", "--dir", "--dir", &home], 5),
        (vec!["run", "download", "-D", "-D", &home], 5),
        (vec!["run", "download", "--dir", "-D", &home], 5),
        (vec!["run", "download", "--dir", "-R", &home], 5),
        (vec!["run", "download", "--dir", "--name", &home], 5),
        (vec!["run", "download", "--dir", "--", &home], 5),
        // `--dir` or `-D` as the value of every other valued option of `run download`.
        (vec!["run", "download", "-R", "-D", &home], 5),
        (vec!["run", "download", "--repo", "--dir", &home], 5),
        (vec!["run", "download", "-p", "--dir", &home], 5),
        (vec!["run", "download", "--pattern", "-D", &home], 5),
        // Not `run download` as the first two words.
        (vec!["--", "run", "download", "--dir", &home], 5),
        (vec!["run", "run", "download", "--dir", &home], 5),
        (vec!["--help", "run", "download", "--dir", &home], 5),
        (vec!["Run", "download", "--dir", &home], 4),
        (vec!["run", "download ", "--dir", &home], 4),
    ];
    // A value attached to another option: the home path after it is the run id.
    for word in &attached {
        cases.push((vec!["run", "download", word, &home], 4));
    }
    for (args, argument) in cases {
        scan_refused(&gh_scanned(&args), argument, &["personal-paths"]);
    }
}

#[test]
fn run_download_directory_values_that_stay_local_pass_the_scan() {
    let home = home();
    let a = format!("{home}/a");
    let b = format!("{home}/b");
    let lines = format!("{a}\n{b}");
    for args in [
        // Several directories: `gh` keeps the last; every one is a local path.
        &["run", "download", "1", "--dir", &a, "-D", &b][..],
        &["run", "download", "1", "--dir", ""],
        &["run", "download", "1", "--dir="],
        &["run", "download", "1", "--dir", &lines],
        &["run", "download", "1", "--dir", "-n"],
    ] {
        scan_passed(&gh_scanned(args));
    }
}

#[test]
fn run_download_directory_breaking_another_rule_on_a_later_line_is_refused() {
    let value = format!("{}/a\n{}", home(), literal());
    let run = gh_scanned(&["run", "download", "1", "--dir", &value]);
    let named = "argument 5 breaks 1 private rule(s): line 2 private-identifiers;";
    assert!(!run.ok, "{}", run.stderr);
    assert!(run.stderr.contains(named), "{named}: {}", run.stderr);
    assert!(!run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
}

#[test]
fn run_download_directory_that_is_not_utf8_never_reaches_the_token_step() {
    use std::{ffi::OsStr, os::unix::ffi::OsStrExt};
    let mut value = b"\xff".to_vec();
    value.extend_from_slice(home().as_bytes());
    let sandbox = Sandbox::new().with_policy();
    let mut command = sandbox.command();
    command
        .arg("--repo")
        .arg(sandbox.path())
        .args(["gh", "--", "run", "download", "1", "--dir"])
        .arg(OsStr::from_bytes(&value));
    let run = sandbox.run(command);
    assert!(!run.ok, "{}", run.stderr);
    assert!(!run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
}

// `gh -- release create|upload <tag> <asset>...`: an asset argument is `<path>` or
// `<path>#<label>`. `gh` sends the file's content and its base name or the label, and never the
// directory part of the path. So `personal-paths` does not apply to the argument's text while
// every other rule does, the base name and the label are scanned in full on their own, and the
// content is scanned: an ELF executable the way `scan-artifact` scans it, any other file as
// UTF-8 text. Nothing else changes: the tag and every option value are scanned as text, and no
// other verb or command is admitted.

/// A directory under the home directory, removed on drop. `personal-paths` matches its path:
/// `release_tag_and_option_values_are_scanned_as_text` refuses it as text.
fn home_dir() -> tempfile::TempDir {
    let home = std::env::var_os("HOME").expect("HOME names the home directory");
    tempfile::Builder::new()
        .prefix("gates-release-asset-")
        .tempdir_in(home)
        .unwrap()
}

/// A file `name` holding `bytes` in `dir`, as the absolute path `gh` is given.
fn put(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> String {
    let path = dir.path().join(name);
    fs::write(&path, bytes).unwrap();
    path.to_str().unwrap().to_owned()
}

/// Refused with `message` before the token step, without showing `hidden`.
fn refused_with(run: &Run, message: &str, hidden: &str) {
    assert!(!run.ok, "{}", run.stderr);
    assert!(run.stderr.contains(message), "{message}: {}", run.stderr);
    assert!(!run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
    assert!(
        hidden.is_empty() || !run.stderr.contains(hidden),
        "{}",
        run.stderr
    );
}

/// The binary asset cases run the pinned scanner, as `scan-artifact` does; they never skip.
fn scanner_set() {
    assert!(
        std::env::var_os("B10X_GATES_GITLEAKS").is_some(),
        "set B10X_GATES_GITLEAKS to the pinned scanner; this test must not skip"
    );
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn elf_section(
    bytes: &mut [u8],
    at: usize,
    name: u32,
    kind: u32,
    flags: u64,
    from: usize,
    size: usize,
) {
    put_u32(bytes, at, name);
    put_u32(bytes, at + 4, kind);
    put_u64(bytes, at + 8, flags);
    put_u64(bytes, at + 24, from as u64);
    put_u64(bytes, at + 32, size as u64);
    put_u64(bytes, at + 48, 1);
}

/// A minimal ELF64 little-endian executable with one executable and one data section, built as
/// `tests/artifact.rs` builds it.
fn elf64(text: &[u8], data: &[u8]) -> Vec<u8> {
    const HEADER: usize = 64;
    const SECTION: usize = 64;
    const NAMES: &[u8] = b"\0.text\0.data\0.bss\0.shstrtab\0";
    let text_at = HEADER;
    let data_at = text_at + text.len();
    let names_at = data_at + data.len();
    let sections_at = (names_at + NAMES.len() + 7) & !7;
    let mut bytes = vec![0u8; sections_at + 5 * SECTION];
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(&mut bytes, 16, 2);
    put_u16(&mut bytes, 18, 62);
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 40, sections_at as u64);
    put_u16(&mut bytes, 52, HEADER as u16);
    put_u16(&mut bytes, 58, SECTION as u16);
    put_u16(&mut bytes, 60, 5);
    put_u16(&mut bytes, 62, 4);
    bytes[text_at..data_at].copy_from_slice(text);
    bytes[data_at..names_at].copy_from_slice(data);
    bytes[names_at..names_at + NAMES.len()].copy_from_slice(NAMES);
    elf_section(
        &mut bytes,
        sections_at + SECTION,
        1,
        1,
        0x6,
        text_at,
        text.len(),
    );
    elf_section(
        &mut bytes,
        sections_at + 2 * SECTION,
        7,
        1,
        0x3,
        data_at,
        data.len(),
    );
    elf_section(
        &mut bytes,
        sections_at + 3 * SECTION,
        13,
        8,
        0x3,
        names_at,
        128,
    );
    elf_section(
        &mut bytes,
        sections_at + 4 * SECTION,
        18,
        3,
        0,
        names_at,
        NAMES.len(),
    );
    bytes
}

/// Clean assets under the home directory: notes, checksums, an executable and the checksums
/// with a label. Every asset costs one run of the pinned scanner, so the passing cases are
/// split over a few tests that run in parallel.
struct Assets {
    _dir: tempfile::TempDir,
    notes: String,
    sums: String,
    binary: String,
    labelled: String,
}

fn clean_assets() -> Assets {
    scanner_set();
    let dir = home_dir();
    let notes = put(&dir, "release-notes.md", b"Fixes.\n");
    let sums = put(&dir, "SHA256SUMS", b"0123abcd  b10x-gates-linux-x86_64\n");
    let binary = put(
        &dir,
        "b10x-gates-linux-x86_64",
        &elf64(b"\x90\x90", b"safe release metadata\n"),
    );
    let labelled = format!("{sums}#Checksums (SHA-256)");
    Assets {
        _dir: dir,
        notes,
        sums,
        binary,
        labelled,
    }
}

#[test]
fn release_assets_under_the_home_directory_pass_the_scan() {
    let a = clean_assets();
    for args in [
        // The release process's own command.
        &[
            "release",
            "create",
            "0.1.32",
            "-R",
            "o/r",
            "--verify-tag",
            "--title",
            "0.1.32",
            "--notes-file",
            &a.notes,
            &a.binary,
            &a.sums,
        ][..],
        &["release", "create", "v1", &a.labelled],
        &["release", "upload", "v1", &a.labelled],
    ] {
        scan_passed(&gh_scanned(args));
    }
}

#[test]
fn release_create_options_take_their_values_as_gh_reads_them() {
    let a = clean_assets();
    for args in [
        &[
            "release",
            "create",
            "-d",
            "-p",
            "--latest=false",
            "--generate-notes",
            "--title=0.1.32",
            "v1",
            &a.binary,
        ][..],
        &["release", "create", "-dpt", "T", "v1", &a.sums],
        &["release", "create", "-tT", "v1", &a.sums],
        &[
            "release",
            "create",
            "v1",
            "--draft=false",
            "--notes",
            "n",
            "--target",
            "main",
            "--discussion-category",
            "c",
            "--notes-start-tag",
            "v0",
            "--notes-from-tag",
            "--fail-on-no-commits",
            "--prerelease",
            &a.sums,
        ],
    ] {
        scan_passed(&gh_scanned(args));
    }
}

#[test]
fn release_upload_options_take_their_values_as_gh_reads_them() {
    let a = clean_assets();
    for args in [
        &[
            "release",
            "upload",
            "v1",
            &a.binary,
            &a.sums,
            "--clobber",
            "-R",
            "o/r",
        ][..],
        &["release", "upload", "--repo=o/r", "v1", &a.sums],
    ] {
        scan_passed(&gh_scanned(args));
    }
}

#[test]
fn release_words_after_the_end_of_options_are_positional() {
    let a = clean_assets();
    for args in [
        // After `--` every word is positional: the tag first, then assets.
        &["release", "create", "v1", "--", &a.sums][..],
        &["release", "upload", "--", "v1", &a.sums],
        // `--` as the value of `--title` does not end the options.
        &["release", "create", "v1", "--title", "--", &a.sums],
    ] {
        scan_passed(&gh_scanned(args));
    }
}

#[test]
fn release_create_takes_several_assets() {
    let a = clean_assets();
    scan_passed(&gh_scanned(&[
        "release", "create", "v1", &a.sums, &a.binary,
    ]));
}

#[test]
fn release_tag_and_option_values_are_scanned_as_text() {
    // Each value is the path of a clean file under the home directory: read as an asset it
    // would pass.
    let dir = home_dir();
    let clean = put(&dir, "clean.txt", b"clean\n");
    let title = format!("--title={clean}");
    let repo = format!("--repo={clean}");
    let attached = format!("-t={clean}");
    for (args, argument) in [
        (&["release", "create", &clean][..], 3),
        (&["release", "create", &clean, &clean], 3),
        (&["release", "upload", &clean, &clean], 3),
        (&["release", "create", "v1", "--title", &clean], 5),
        (&["release", "create", "v1", "-t", &clean], 5),
        (&["release", "create", "v1", &title], 4),
        (&["release", "create", "v1", &attached], 4),
        (&["release", "create", "v1", "-dt", &clean], 5),
        (&["release", "create", "v1", "--notes", &clean], 5),
        (&["release", "create", "v1", "-n", &clean], 5),
        // `-F` is scanned as before: its value as text.
        (&["release", "create", "v1", "-F", &clean], 5),
        (&["release", "create", "v1", "--target", &clean], 5),
        (
            &["release", "create", "v1", "--discussion-category", &clean],
            5,
        ),
        (&["release", "create", "v1", "--notes-start-tag", &clean], 5),
        (&["release", "create", "v1", "--repo", &clean], 5),
        (&["release", "create", "v1", "-R", &clean], 5),
        (&["release", "create", "v1", &repo], 4),
        (&["release", "upload", "v1", "-R", &clean], 5),
        (&["release", "upload", "v1", "--repo", &clean], 5),
        (&["release", "upload", "v1", &repo], 4),
        // A valued option takes the next word even when it is an option; the path after it
        // is then the tag.
        (&["release", "create", "--title", "--draft", &clean], 5),
        (&["release", "upload", "-R", "--clobber", &clean], 5),
        // After `--` the first positional is the tag.
        (&["release", "create", "--", &clean, &clean], 4),
    ] {
        scan_refused(&gh_scanned(args), argument, &["personal-paths"]);
    }
}

#[test]
fn release_notes_file_content_is_still_scanned() {
    let dir = home_dir();
    let literal = literal();
    let notes = put(&dir, "notes.md", format!("Fixes.\n{literal}\n").as_bytes());
    let sums = put(&dir, "SHA256SUMS", b"clean\n");
    refused_with(
        &gh_scanned(&["release", "create", "v1", "--notes-file", &notes, &sums]),
        "argument 5, the file it names, breaks 1 private rule(s): line 2 private-identifiers;",
        &literal,
    );
}

#[test]
fn release_asset_name_or_label_breaking_a_rule_is_refused() {
    let dir = home_dir();
    let literal = literal();
    let sums = put(&dir, "SHA256SUMS", b"clean\n");
    let private_name = put(&dir, &format!("{literal}.txt"), b"clean\n");
    // A base name may hold a home directory in another system's spelling.
    let home_name = put(
        &dir,
        &["c:", "users", "fixture-person"].join("\\"),
        b"clean\n",
    );
    let private_label = format!("{sums}#{literal}");
    let home_label = format!("{sums}#{}/x", home());
    for (args, message) in [
        (
            ["release", "create", "v1", &private_name],
            "argument 4 breaks 1 private rule(s): line 1 private-identifiers;",
        ),
        (
            ["release", "upload", "v1", &private_label],
            "argument 4 breaks 1 private rule(s): line 1 private-identifiers;",
        ),
        (
            ["release", "create", "v1", &home_name],
            "argument 4, the asset's name, breaks 1 private rule(s): line 1 personal-paths;",
        ),
        (
            ["release", "upload", "v1", &home_label],
            "argument 4, the asset's label, breaks 1 private rule(s): line 1 personal-paths;",
        ),
    ] {
        refused_with(&gh_scanned(&args), message, &literal);
    }
}

#[test]
fn release_asset_content_breaking_a_rule_is_refused() {
    scanner_set();
    let sandbox = Sandbox::new().with_policy();
    let dir = home_dir();
    let literal = literal();
    let text = put(&dir, "notes.txt", format!("clean\n{literal}\n").as_bytes());
    let home_text = put(&dir, "paths.txt", format!("{}/x\n", home()).as_bytes());
    let binary = put(&dir, "tool", &elf64(b"\x90\x90", literal.as_bytes()));
    let opaque = put(&dir, "blob.bin", b"\x00\xff\xfe\x00");
    for (args, message) in [
        (
            vec!["release", "create", "v1", &text],
            "argument 4, the asset it names, breaks 1 private rule(s): line 2 private-identifiers;",
        ),
        (
            vec!["release", "upload", "v1", &home_text],
            "argument 4, the asset it names, breaks 1 private rule(s): line 1 personal-paths;",
        ),
        (
            vec!["release", "upload", "v1", &binary],
            "argument 4, the asset it names: artifact breaks ",
        ),
        (
            vec!["release", "create", "v1", &opaque],
            "argument 4, the asset it names, is neither an ELF, Mach-O or PE executable nor UTF-8 text",
        ),
        (
            vec!["release", "create", "v1", "--", &text],
            "argument 5, the asset it names, breaks 1 private rule(s): line 2 private-identifiers;",
        ),
        (
            vec!["release", "upload", "--", "v1", &text],
            "argument 5, the asset it names, breaks 1 private rule(s): line 2 private-identifiers;",
        ),
    ] {
        refused_with(&gh_in(&sandbox, &args), message, &literal);
    }
}

#[test]
fn relative_release_asset_is_read_against_the_repo() {
    // `gh` runs in `--repo`; the working directory of `b10x-gates` holds a clean file of the
    // same name.
    let sandbox = Sandbox::new().with_policy();
    let repo = sandbox.path().join("repo");
    fs::create_dir(&repo).unwrap();
    fs::write(repo.join("asset.txt"), format!("{}\n", literal())).unwrap();
    sandbox.file("asset.txt", b"clean\n");
    let mut command = sandbox.command();
    command
        .arg("--repo")
        .arg(&repo)
        .args(["gh", "--", "release", "upload", "v1", "asset.txt"]);
    refused_with(
        &sandbox.run(command),
        "argument 4, the asset it names, breaks 1 private rule(s): line 1 private-identifiers;",
        &literal(),
    );
}

#[test]
fn release_binary_asset_is_scanned_as_scan_artifact_scans_it() {
    scanner_set();
    // A three-byte literal inside instruction bytes: the text rules find it in the file's
    // bytes; `scan-artifact` reads printable runs of four bytes or more there, so it does not.
    let short = "%&%";
    let sandbox = Sandbox::new().with_literals(&[short]);
    let dir = home_dir();
    let binary = put(
        &dir,
        "tool",
        &elf64(b"\x90%&%\x90", b"safe release metadata\n"),
    );
    scan_passed(&gh_in(&sandbox, &["release", "create", "v1", &binary]));
    scan_passed(&gh_in(&sandbox, &["release", "upload", "v1", &binary]));
    // The same file read by the text rules, as a notes file, is refused.
    refused_with(
        &gh_in(
            &sandbox,
            &["release", "create", "v1", "--notes-file", &binary],
        ),
        "argument 5, the file it names, breaks 1 private rule(s)",
        short,
    );
    // In a data section the literal is refused by the artifact scan too.
    let data = put(
        &dir,
        "data-tool",
        &elf64(b"\x90\x90", b"safe %&% metadata\n"),
    );
    refused_with(
        &gh_in(&sandbox, &["release", "upload", "v1", &data]),
        "argument 4, the asset it names: artifact breaks ",
        short,
    );
}

#[test]
fn release_asset_that_cannot_be_read_is_refused() {
    let dir = home_dir();
    put(&dir, "a.txt", b"clean\n");
    let missing = dir.path().join("missing.txt").to_str().unwrap().to_owned();
    let directory = dir.path().to_str().unwrap().to_owned();
    let pattern = format!("{directory}/*.txt");
    for (args, message) in [
        (
            vec!["release", "create", "v1", &missing],
            "argument 4, the asset it names, unreadable",
        ),
        (
            vec!["release", "upload", "v1", &directory],
            "argument 4, the asset it names, is not a regular file",
        ),
        (
            vec!["release", "upload", "v1", &pattern],
            "argument 4 is a file pattern",
        ),
        // After `--`, `--title` is an asset and not the option.
        (
            vec!["release", "create", "v1", "--", "--title"],
            "argument 5, the asset it names, unreadable",
        ),
    ] {
        refused_with(&gh_scanned(&args), message, "");
    }
}

#[test]
fn release_asset_over_the_read_bound_is_refused() {
    // Sparse: one byte over 128 MiB without the disk space.
    let dir = home_dir();
    let large = dir.path().join("large.txt");
    fs::File::create(&large)
        .unwrap()
        .set_len(128 * 1024 * 1024 + 1)
        .unwrap();
    refused_with(
        &gh_scanned(&["release", "upload", "v1", large.to_str().unwrap()]),
        "argument 4, the asset it names, is larger than 128 MiB",
        "",
    );
}

#[test]
fn release_asset_behind_a_symbolic_link_is_read_as_gh_reads_it() {
    scanner_set();
    let dir = home_dir();
    let target = put(&dir, "SHA256SUMS", b"clean\n");
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let link = link.to_str().unwrap().to_owned();
    scan_passed(&gh_scanned(&["release", "upload", "v1", &link]));
    fs::write(&target, format!("{}\n", literal())).unwrap();
    refused_with(
        &gh_scanned(&["release", "upload", "v1", &link]),
        "argument 4, the asset it names, breaks 1 private rule(s)",
        &literal(),
    );
}

#[test]
fn release_option_the_asset_scan_does_not_know_is_refused() {
    // A relative asset whose content would break a rule: with an unknown option no word is
    // read as an asset, the text scan passes, and the command is still refused.
    let sums = "SHA256SUMS";
    for (args, argument) in [
        (["release", "create", "v1", "--unknown", sums], 4),
        (["release", "create", "v1", "-x", sums], 4),
        (["release", "create", "v1", "-dx", sums], 4),
        (["release", "upload", "v1", "--title", sums], 4),
        (["release", "upload", "v1", "-d", sums], 4),
    ] {
        let sandbox = Sandbox::new().with_policy();
        sandbox.file(sums, format!("{}\n", literal()).as_bytes());
        refused_with(
            &gh_in(&sandbox, &args),
            &format!("argument {argument} is an option the asset scan does not know"),
            "",
        );
    }
}

#[test]
fn home_paths_stay_refused_for_every_other_release_verb_and_command() {
    let dir = home_dir();
    let clean = put(&dir, "clean.txt", b"clean\n");
    for (args, argument) in [
        (&["release", "view", &clean][..], 3),
        (&["release", "delete", &clean], 3),
        (&["release", "download", "v1", "--dir", &clean], 5),
        (&["release", "edit", "v1", "--title", &clean], 5),
        (&["release", "delete-asset", "v1", &clean], 4),
        (&["release", "new", "v1", &clean], 4),
        (&["Release", "create", "v1", &clean], 4),
        (&["release", "Create", "v1", &clean], 4),
        (&["release", "release", "create", "v1", &clean], 5),
        (&["-R", "o/r", "release", "create", "v1", &clean], 6),
        (&["--", "release", "upload", "v1", &clean], 5),
        (&["run", "download", "1", &clean], 4),
        (&["pr", "create", "--title", &clean], 4),
    ] {
        scan_refused(&gh_scanned(args), argument, &["personal-paths"]);
    }
}

// Security review of the admission (review/release-asset-paths).

#[test]
fn release_asset_that_is_a_fifo_is_refused_without_blocking() {
    // `fs::read` of a FIFO waits for a writer that never comes. A path that is not a regular
    // file is refused before it is read, so the command ends.
    let sandbox = Sandbox::new().with_policy();
    let dir = home_dir();
    let fifo = dir.path().join("asset.fifo");
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let fifo = fifo.to_str().unwrap().to_owned();
    let mut command = sandbox.command();
    command
        .arg("--repo")
        .arg(sandbox.path())
        .args(["gh", "--", "release", "upload", "v1", &fifo])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().unwrap();
    let started = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if started.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("a FIFO named as a release asset blocked the scan for 10 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let output = child.wait_with_output().unwrap();
    refused_with(
        &Run {
            ok: output.status.success(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        },
        "argument 4",
        "",
    );
}

#[test]
fn release_text_asset_carrying_a_secret_is_refused() {
    // An ELF asset goes through the secret scanner; a text asset only through the private
    // rules, so a credential in a text file under the home directory is admitted.
    scanner_set();
    let dir = home_dir();
    let token = format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let line = format!("token = '{token}'\n");
    let binary = put(&dir, "tool", &elf64(b"\x90\x90", line.as_bytes()));
    let text = put(&dir, "settings.env", line.as_bytes());
    refused_with(
        &gh_scanned(&["release", "upload", "v1", &binary]),
        "argument 4, the asset it names: artifact breaks secrets rule",
        &token,
    );
    refused_with(
        &gh_scanned(&["release", "upload", "v1", &text]),
        "argument 4, the asset it names",
        &token,
    );
}

// A gzip-compressed tar asset, known by its content and not by its name, is admitted when
// every member passes: each regular file is scanned as an asset is (an ELF executable as
// `scan-artifact` scans it, any other file as UTF-8 text with the private rules and the pinned
// secret scanner), a directory carries nothing, and every member name is scanned with every
// rule. Anything else is refused, naming the argument and the member. The fixtures are written
// here header by header; nothing is unpacked to disk.

/// One tar header block as GNU tar writes it, changed by `edit`, with its checksum.
fn tar_block(name: &[u8], kind: u8, size: usize, edit: impl FnOnce(&mut [u8; 512])) -> [u8; 512] {
    let mut block = [0u8; 512];
    block[..name.len()].copy_from_slice(name);
    block[100..108].copy_from_slice(b"0000644\0");
    block[108..116].copy_from_slice(b"0001750\0");
    block[116..124].copy_from_slice(b"0001750\0");
    block[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
    block[136..148].copy_from_slice(b"15302322065\0");
    block[156] = kind;
    block[257..265].copy_from_slice(b"ustar  \0");
    block[265..272].copy_from_slice(b"builder");
    block[297..304].copy_from_slice(b"builder");
    edit(&mut block);
    block[148..156].copy_from_slice(b"        ");
    let sum: u32 = block.iter().map(|&b| u32::from(b)).sum();
    block[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    block
}

/// A POSIX ustar header of a regular file: `prefix` and `name` are joined with a `/`.
fn ustar_block(prefix: &[u8], name: &[u8], size: usize) -> [u8; 512] {
    tar_block(name, b'0', size, |block| {
        block[257..265].copy_from_slice(b"ustar\x0000");
        block[265..345].fill(0);
        block[345..345 + prefix.len()].copy_from_slice(prefix);
    })
}

/// A tar stream, built member by member.
#[derive(Default)]
struct Tar(Vec<u8>);

impl Tar {
    /// A header block and `data`, padded to whole blocks.
    fn block(mut self, header: [u8; 512], data: &[u8]) -> Self {
        self.0.extend_from_slice(&header);
        self.0.extend_from_slice(data);
        self.0.resize(self.0.len().div_ceil(512) * 512, 0);
        self
    }

    fn file(self, name: &str, data: &[u8]) -> Self {
        self.block(tar_block(name.as_bytes(), b'0', data.len(), |_| {}), data)
    }

    fn dir(self, name: &str) -> Self {
        self.block(tar_block(name.as_bytes(), b'5', 0, |_| {}), &[])
    }

    /// An entry of type `kind` without data, naming a target as a link does.
    fn entry(self, name: &str, kind: u8) -> Self {
        self.block(
            tar_block(name.as_bytes(), kind, 0, |block| {
                block[157..163].copy_from_slice(b"target");
            }),
            &[],
        )
    }

    /// A GNU long name entry: the next member's name.
    fn long_name(self, name: &[u8]) -> Self {
        let mut data = name.to_vec();
        data.push(0);
        self.block(tar_block(b"././@LongLink", b'L', data.len(), |_| {}), &data)
    }

    fn raw(mut self, bytes: &[u8]) -> Self {
        self.0.extend_from_slice(bytes);
        self
    }

    /// The end marker, two zero blocks, padded to the 10,240-byte record GNU tar writes.
    fn end(self) -> Vec<u8> {
        let mut bytes = self.raw(&[0; 1024]).0;
        bytes.resize(bytes.len().div_ceil(10_240) * 10_240, 0);
        bytes
    }
}

/// The top directory of the release archives here.
const TOP: &str = "tool-1.0.0-x86_64-unknown-linux-gnu";

/// A release archive as a release process packs it: a directory holding a README, the
/// executable, an assessor file and a licence.
fn release_tar() -> Tar {
    Tar::default()
        .dir(&format!("{TOP}/"))
        .file(
            &format!("{TOP}/README.md"),
            b"# tool\n\nRun `tool --help`.\n",
        )
        .file(
            &format!("{TOP}/tool"),
            &elf64(b"\x90\x90", b"safe release metadata\n"),
        )
        .file(&format!("{TOP}/tool.assessor.yaml"), b"name: tool\n")
        .file(&format!("{TOP}/LICENSE"), b"Apache License\nVersion 2.0\n")
}

/// A gzip-compressed archive of the top directory, then whatever `members` adds.
fn archive(members: impl FnOnce(Tar) -> Tar) -> Vec<u8> {
    gzip(&members(Tar::default().dir(&format!("{TOP}/"))).end())
}

/// `gh -- release upload v1 <archive>` with the archive under the home directory.
fn upload_archive(bytes: &[u8]) -> Run {
    let dir = home_dir();
    let asset = put(&dir, &format!("{TOP}.tar.gz"), bytes);
    gh_scanned(&["release", "upload", "v1", &asset])
}

/// The prefix every refusal of the archive asset of `upload_archive` starts with.
const ARCHIVE: &str = "argument 4, the asset it names,";

#[test]
fn release_archive_of_files_and_directories_passes_the_scan() {
    scanner_set();
    let dir = home_dir();
    let bytes = gzip(&release_tar().end());
    let named = put(&dir, &format!("{TOP}.tar.gz"), &bytes);
    let notes = put(&dir, "notes.md", b"Fixes.\n");
    scan_passed(&gh_scanned(&[
        "release",
        "create",
        "v1",
        "--notes-file",
        &notes,
        &named,
    ]));
    // Known by its content: the same archive under another name.
    let unnamed = put(&dir, "tool.bin", &bytes);
    scan_passed(&gh_scanned(&["release", "upload", "v1", &unnamed]));
}

#[test]
fn release_archive_with_long_and_prefixed_names_passes_the_scan() {
    scanner_set();
    let long = format!("{TOP}/{}/notes.txt", "nested".repeat(20));
    let readme = b"Read me.\n";
    let bytes = archive(|tar| {
        tar.long_name(long.as_bytes())
            .file("././@LongLink", b"clean\n")
            .block(
                ustar_block(TOP.as_bytes(), b"README.md", readme.len()),
                readme,
            )
    });
    scan_passed(&upload_archive(&bytes));
}

/// A gzip stream of `tar` whose header carries what `header` sets.
fn gzip_with(header: flate2::GzBuilder, tar: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut encoder = header.write(Vec::new(), flate2::Compression::fast());
    encoder.write_all(tar).unwrap();
    encoder.finish().unwrap()
}

#[test]
fn release_archive_member_breaking_a_rule_is_refused() {
    scanner_set();
    let literal = literal();
    let text = format!("clean\n{literal}\n");
    let token = format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let secret = format!("token = '{token}'\n");
    let tar = release_tar().end();
    let cases: Vec<(Vec<u8>, String)> = vec![
        (
            archive(|tar| tar.file(&format!("{TOP}/README.md"), text.as_bytes())),
            format!(
                "{ARCHIVE} member 2 `{TOP}/README.md`, breaks 1 private rule(s): line 2 \
                 private-identifiers;"
            ),
        ),
        (
            archive(|tar| {
                tar.file(
                    &format!("{TOP}/tool"),
                    &elf64(b"\x90\x90", literal.as_bytes()),
                )
            }),
            format!("{ARCHIVE} member 2 `{TOP}/tool`: artifact breaks "),
        ),
        (
            archive(|tar| tar.file(&format!("{TOP}/settings.env"), secret.as_bytes())),
            format!("{ARCHIVE} member 2 `{TOP}/settings.env`, breaks secrets rule"),
        ),
        (
            archive(|tar| tar.file(&format!("{TOP}/{literal}.txt"), b"clean\n")),
            format!(
                "{ARCHIVE} the name of member 2, breaks 1 private rule(s): line 1 \
                 private-identifiers;"
            ),
        ),
        (
            archive(|tar| tar.dir(&format!("{TOP}/{literal}/"))),
            format!("{ARCHIVE} the name of member 2, breaks 1 private rule(s)"),
        ),
        (
            archive(|tar| tar.file(&format!("{}/notes.txt", home()), b"clean\n")),
            format!(
                "{ARCHIVE} the name of member 2, breaks 1 private rule(s): line 1 personal-paths;"
            ),
        ),
        (
            archive(|tar| {
                tar.long_name(format!("{TOP}/{}/{literal}", "nested".repeat(20)).as_bytes())
                    .file("././@LongLink", b"clean\n")
            }),
            format!("{ARCHIVE} the name of member 2, breaks 1 private rule(s)"),
        ),
        (
            archive(|tar| {
                let readme = b"Read me.\n";
                tar.block(
                    ustar_block(literal.as_bytes(), b"README.md", readme.len()),
                    readme,
                )
            }),
            format!("{ARCHIVE} the name of member 2, breaks 1 private rule(s)"),
        ),
        (
            gzip_with(
                flate2::GzBuilder::new().filename(format!("{literal}.tar")),
                &tar,
            ),
            format!("{ARCHIVE} the gzip header's file name, breaks 1 private rule(s)"),
        ),
        (
            gzip_with(flate2::GzBuilder::new().comment(literal.as_bytes()), &tar),
            format!("{ARCHIVE} the gzip header's comment, breaks 1 private rule(s)"),
        ),
        (
            gzip_with(
                flate2::GzBuilder::new().extra(b"XY\x02\x00ab".to_vec()),
                &tar,
            ),
            format!("{ARCHIVE} carries a gzip extra field, which the scan does not read"),
        ),
    ];
    for (bytes, message) in cases {
        let run = upload_archive(&bytes);
        refused_with(&run, &message, &literal);
        assert!(!run.stderr.contains(&token), "{}", run.stderr);
    }
}

#[test]
fn release_archive_member_neither_elf_nor_text_is_refused() {
    let nested = gzip(&release_tar().end());
    for (name, data) in [
        ("blob.bin", &b"\x00\xff\xfe\x00"[..]),
        ("nested.tar.gz", &nested[..]),
    ] {
        refused_with(
            &upload_archive(&archive(|tar| tar.file(&format!("{TOP}/{name}"), data))),
            &format!(
                "{ARCHIVE} member 2 `{TOP}/{name}`, is neither an ELF, Mach-O or PE executable \
                 nor UTF-8 text, so it cannot be scanned"
            ),
            "",
        );
    }
}

#[test]
fn release_archive_entry_that_is_not_a_file_or_directory_is_refused() {
    for (kind, what) in [
        (b'1', "a hard link"),
        (b'2', "a symbolic link"),
        (b'3', "a character device"),
        (b'4', "a block device"),
        (b'6', "a FIFO"),
        (b'7', "an entry of type `7`"),
        (b'x', "an entry of type `x`"),
        (b'g', "an entry of type `g`"),
        (b'K', "an entry of type `K`"),
        (b'S', "an entry of type `S`"),
        (b'D', "an entry of type `D`"),
    ] {
        refused_with(
            &upload_archive(&archive(|tar| tar.entry(&format!("{TOP}/entry"), kind))),
            &format!(
                "{ARCHIVE} member 2 `{TOP}/entry`, is {what}, not a regular file or a directory"
            ),
            "",
        );
    }
    // A directory carries no data; one that does is not read as a directory.
    refused_with(
        &upload_archive(&archive(|tar| {
            tar.block(
                tar_block(format!("{TOP}/data/").as_bytes(), b'5', 6, |_| {}),
                b"clean\n",
            )
        })),
        &format!("{ARCHIVE} member 2 `{TOP}/data/`, is a directory that carries data"),
        "",
    );
}

#[test]
fn release_archive_member_name_leaving_the_archive_is_refused() {
    let escape = |name: &str| {
        format!("{ARCHIVE} member 2 `{name}`, is an absolute path or has a `..` component")
    };
    for name in [
        "/etc/tool",
        "../tool",
        "a/../../tool",
        "..",
        "a/..",
        "a/../b",
    ] {
        refused_with(
            &upload_archive(&archive(|tar| tar.file(name, b"clean\n"))),
            &escape(name),
            "",
        );
    }
    let long = format!("{}../tool", "a/".repeat(60));
    refused_with(
        &upload_archive(&archive(|tar| {
            tar.long_name(long.as_bytes())
                .file("././@LongLink", b"clean\n")
        })),
        &escape(&long),
        "",
    );
    refused_with(
        &upload_archive(&archive(|tar| {
            tar.block(ustar_block(b"/abs", b"tool", 6), b"clean\n")
        })),
        &escape("/abs/tool"),
        "",
    );
    refused_with(
        &upload_archive(&archive(|tar| tar.file("", b"clean\n"))),
        &format!("{ARCHIVE} member 2, has an empty name"),
        "",
    );
    refused_with(
        &upload_archive(&archive(|tar| {
            tar.block(tar_block(b"tool\xff", b'0', 6, |_| {}), b"clean\n")
        })),
        &format!("{ARCHIVE} member 2, has a name that is not UTF-8 text"),
        "",
    );
}

#[test]
fn release_archive_that_cannot_be_read_is_refused() {
    let unreadable =
        |reason: &str| format!("{ARCHIVE} is a gzip archive the scan cannot read: {reason}");
    let corrupt = unreadable("the gzip stream is corrupt or cut short");
    let clean = gzip(&release_tar().end());
    let cut = clean[..clean.len() - 10].to_vec();
    let mut crc = clean.clone();
    let at = crc.len() - 8;
    crc[at] ^= 0xff;
    let mut corrupt_header = tar_block(b"tool/notes.txt", b'0', 6, |_| {});
    corrupt_header[0] ^= 0x01;
    let text = "text that is not a tar stream\n".repeat(40);
    let size = |field: &[u8; 12]| {
        let field = *field;
        archive(move |tar| {
            tar.block(
                tar_block(b"tool/notes.txt", b'0', 6, |block| {
                    block[124..136].copy_from_slice(&field);
                }),
                b"clean\n",
            )
        })
    };
    let cases: Vec<(Vec<u8>, String)> = vec![
        (cut, corrupt.clone()),
        (crc, corrupt.clone()),
        (b"\x1f\x8b\x08\x00\xff\xfe\x00".to_vec(), corrupt),
        (
            gzip(text.as_bytes()),
            unreadable("the tar header of member 1 is corrupt"),
        ),
        (
            archive(|tar| tar.block(corrupt_header, b"clean\n")),
            unreadable("the tar header of member 2 is corrupt"),
        ),
        (
            archive(|tar| {
                tar.block(
                    tar_block(b"tool/notes.txt", b'0', 6, |block| block[257..265].fill(0)),
                    b"clean\n",
                )
            }),
            unreadable("the tar header of member 2 is neither ustar nor GNU"),
        ),
        (
            size(b"0000000000x\0"),
            unreadable("the size of member 2 is not an octal number"),
        ),
        (
            size(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6]),
            unreadable("the size of member 2 is not an octal number"),
        ),
        (
            gzip(
                &Tar::default()
                    .dir("tool/")
                    .raw(&tar_block(b"tool/notes.txt", b'0', 4096, |_| {}))
                    .raw(b"clean\n")
                    .0,
            ),
            unreadable("member 2 is cut short"),
        ),
        (
            gzip(
                &Tar::default()
                    .dir("tool/")
                    .file("tool/notes.txt", b"clean\n")
                    .0,
            ),
            unreadable("the tar stream has no end marker"),
        ),
        (
            gzip(&Tar::default().dir("tool/").raw(&[0; 512]).0),
            unreadable("the tar stream has no end marker"),
        ),
        (
            gzip(&Tar::default().dir("tool/").raw(&[0; 1024]).raw(b"x").0),
            unreadable("data follows the tar end marker"),
        ),
        (
            archive(|tar| tar.long_name(&[b'a'; 4097])),
            unreadable("the GNU long name of member 2 is longer than 4096 bytes"),
        ),
        (
            archive(|tar| {
                tar.long_name(b"tool/a")
                    .long_name(b"tool/b")
                    .file("x", b"clean\n")
            }),
            unreadable("the GNU long name of member 2 names no member"),
        ),
        (
            archive(|tar| tar.long_name(b"tool/a")),
            unreadable("the GNU long name of member 2 names no member"),
        ),
    ];
    for (bytes, message) in cases {
        refused_with(&upload_archive(&bytes), &message, "");
    }
}

#[test]
fn release_archive_with_data_after_the_gzip_stream_is_refused() {
    let clean = gzip(&release_tar().end());
    let follows =
        format!("{ARCHIVE} is a gzip archive the scan cannot read: data follows the gzip stream");
    for tail in [&clean[..], b"\0", b"trailing text\n"] {
        let mut bytes = clean.clone();
        bytes.extend_from_slice(tail);
        refused_with(&upload_archive(&bytes), &follows, "");
    }
}

/// A gzip stream of `header`, then `mebibytes` MiB of 0xff bytes, then the end marker. Each
/// part is compressed on its own into byte-aligned deflate blocks, so the test compresses one
/// mebibyte and repeats it, and checksums one mebibyte and combines it.
fn gzip_bomb(header: [u8; 512], mebibytes: usize) -> Vec<u8> {
    use flate2::{Compress, Compression, Crc, FlushCompress};
    fn deflate(input: &[u8], flush: FlushCompress) -> Vec<u8> {
        let mut compress = Compress::new(Compression::fast(), false);
        let mut out = Vec::with_capacity(input.len() + 1024);
        compress.compress_vec(input, &mut out, flush).unwrap();
        assert_eq!(compress.total_in() as usize, input.len());
        out
    }
    let chunk = vec![0xffu8; 1024 * 1024];
    let block = deflate(&chunk, FlushCompress::Full);
    let mut chunk_crc = Crc::new();
    chunk_crc.update(&chunk);
    let end = [0u8; 1024];
    let mut crc = Crc::new();
    let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    bytes.extend(deflate(&header, FlushCompress::Full));
    crc.update(&header);
    for _ in 0..mebibytes {
        bytes.extend_from_slice(&block);
        crc.combine(&chunk_crc);
    }
    bytes.extend(deflate(&end, FlushCompress::Finish));
    crc.update(&end);
    bytes.extend(crc.sum().to_le_bytes());
    bytes.extend(crc.amount().to_le_bytes());
    bytes
}

#[test]
fn release_archive_unpacking_over_the_read_bound_is_refused() {
    let over = format!(
        "{ARCHIVE} is a gzip archive the scan cannot read: it unpacks to more than 128 MiB, the \
         most the scan reads"
    );
    // 129 MiB of bytes that are not UTF-8 in one member, from well under a mebibyte of gzip.
    let bytes = gzip_bomb(
        tar_block(b"tool/blob", b'0', 129 * 1024 * 1024, |_| {}),
        129,
    );
    assert!(bytes.len() < 1024 * 1024, "{}", bytes.len());
    refused_with(&upload_archive(&bytes), &over, "");
    // 2 GiB from about 2 MiB of gzip, under a 1 GiB address-space limit: the read stops at
    // the bound. A reader that unpacks first and measures after runs out of memory instead.
    let bomb = gzip_bomb(
        tar_block(b"tool/blob", b'0', 2048 * 1024 * 1024, |_| {}),
        2048,
    );
    let sandbox = Sandbox::new().with_policy();
    let dir = home_dir();
    let asset = put(&dir, &format!("{TOP}.tar.gz"), &bomb);
    let inner = sandbox.command();
    let mut command = Command::new("/usr/bin/prlimit");
    command
        .arg(format!("--as={}", 1024 * 1024 * 1024))
        .arg(inner.get_program())
        .current_dir(sandbox.path());
    for (key, value) in inner.get_envs() {
        match value {
            Some(value) => command.env(key, value),
            None => command.env_remove(key),
        };
    }
    command
        .arg("--repo")
        .arg(sandbox.path())
        .args(["gh", "--", "release", "upload", "v1", &asset]);
    refused_with(&sandbox.run(command), &over, "");
}

#[test]
fn release_archive_with_more_members_than_the_bound_is_refused() {
    let directories = |count: usize| {
        let mut tar = Tar::default();
        for i in 0..count {
            tar = tar.dir(&format!("d{i:05}/"));
        }
        gzip(&tar.end())
    };
    scan_passed(&upload_archive(&directories(10_000)));
    refused_with(
        &upload_archive(&directories(10_001)),
        &format!(
            "{ARCHIVE} is a gzip archive the scan cannot read: it holds more than 10000 members, \
             the most the scan reads"
        ),
        "",
    );
}

// A Mach-O executable (thin or universal) and a PE executable are scanned as `scan-artifact`
// scans an ELF executable, with every private rule and the pinned secret scanner; no rule is
// exempted for them. A zip asset is unpacked in memory like a gzip-compressed tar asset and
// admitted member by member. The fixtures are written byte by byte in `support/formats.rs`.

/// A universal file of an arm64 slice and an x86-64 slice built from `text` and `data`.
fn fat(text: &[u8], data: &[u8]) -> Vec<u8> {
    macho_fat(
        &[
            macho64(b"\x90\x90", b"safe release metadata\n"),
            macho64_with(MH_EXECUTE, CPU_X86_64, text, data, None),
        ],
        b"",
    )
}

fn pe64(text: &[u8], data: &[u8]) -> Vec<u8> {
    pe(true, text, data)
}

fn pe32(text: &[u8], data: &[u8]) -> Vec<u8> {
    pe(false, text, data)
}

type Build = fn(&[u8], &[u8]) -> Vec<u8>;

/// Each executable format beside ELF, with a release asset name it would carry.
const EXECUTABLES: [(&str, Build); 4] = [
    ("tool-1.0.0-aarch64-apple-darwin", macho64),
    ("tool-1.0.0-universal-apple-darwin", fat),
    ("tool-1.0.0-x86_64-pc-windows-msvc.exe", pe64),
    ("tool-1.0.0-i686-pc-windows-msvc.exe", pe32),
];

#[test]
fn release_macho_and_pe_assets_pass_the_scan() {
    scanner_set();
    let dir = home_dir();
    for (name, build) in EXECUTABLES {
        let asset = put(&dir, name, &build(b"\x90\x90", b"safe release metadata\n"));
        scan_passed(&gh_scanned(&["release", "upload", "v1", &asset]));
    }
}

#[test]
fn release_archive_holding_a_macho_executable_passes_the_scan() {
    scanner_set();
    let top = "tool-1.0.0-aarch64-apple-darwin";
    let bytes = gzip(
        &Tar::default()
            .dir(&format!("{top}/"))
            .file(
                &format!("{top}/tool"),
                &macho64(b"\x90\x90", b"safe release metadata\n"),
            )
            .file(&format!("{top}/README.md"), b"# tool\n")
            .end(),
    );
    scan_passed(&upload_archive(&bytes));
}

#[test]
fn release_macho_and_pe_assets_breaking_a_rule_are_refused() {
    scanner_set();
    let sandbox = Sandbox::new().with_policy();
    let dir = home_dir();
    let literal = literal();
    let token = format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let secret = format!("token = '{token}'\n");
    let runner = ["", "Users", "runner", "work", "tool", "src", "main.rs"].join("/");
    for (name, build) in EXECUTABLES {
        // A runner's home directory is a personal path like any other: no exemption.
        for (data, rule, hidden) in [
            (literal.as_bytes(), "private-identifiers", &literal[..]),
            (runner.as_bytes(), "personal-paths", &runner[..]),
            (secret.as_bytes(), "secrets rule", &token[..]),
        ] {
            let asset = put(&dir, name, &build(b"\x90\x90", data));
            let run = gh_in(&sandbox, &["release", "upload", "v1", &asset]);
            refused_with(
                &run,
                "argument 4, the asset it names: artifact breaks ",
                hidden,
            );
            assert!(run.stderr.contains(rule), "{name}: {}", run.stderr);
        }
    }
}

#[test]
fn release_asset_of_an_unknown_binary_format_is_refused() {
    let dir = home_dir();
    let mut java = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34];
    java.extend_from_slice(&[0u8; 64]);
    let mut dos = vec![0u8; 128];
    dos[..2].copy_from_slice(b"MZ");
    let mut coff = vec![0x64, 0x86, 0x01, 0x00];
    coff.extend_from_slice(&[0u8; 60]);
    for (name, bytes, message) in [
        (
            "blob.bin",
            b"\x00\xff\xfe\x00".to_vec(),
            "argument 4, the asset it names, is neither an ELF, Mach-O or PE executable nor \
             UTF-8 text, so it cannot be scanned",
        ),
        (
            "tool.o",
            coff,
            "argument 4, the asset it names, is neither an ELF, Mach-O or PE executable nor \
             UTF-8 text, so it cannot be scanned",
        ),
        (
            "Tool.class",
            java,
            "argument 4, the asset it names: artifact format",
        ),
        (
            "tool.com",
            dos,
            "argument 4, the asset it names: artifact format",
        ),
    ] {
        let asset = put(&dir, name, &bytes);
        refused_with(
            &gh_scanned(&["release", "upload", "v1", &asset]),
            message,
            "",
        );
    }
}

/// The top directory of the zip release archives here.
const WIN: &str = "tool-1.0.0-x86_64-pc-windows-msvc";

/// A zip release archive as `zip -q -X -r` packs one: a directory holding a README, a
/// licence stored without compression, and the executable.
fn release_zip() -> Zip {
    Zip::default()
        .dir(&format!("{WIN}/"))
        .file(
            &format!("{WIN}/README.md"),
            b"# tool\n\nRun `tool --help`.\n",
        )
        .entry(ZipEntry::stored(
            &format!("{WIN}/LICENSE"),
            b"Apache License\nVersion 2.0\n",
        ))
        .file(
            &format!("{WIN}/tool.exe"),
            &pe(true, b"\x90\x90", b"safe release metadata\n"),
        )
}

/// A zip archive of the top directory, then whatever `members` adds.
fn zip(members: impl FnOnce(Zip) -> Zip) -> Vec<u8> {
    members(Zip::default().dir(&format!("{WIN}/"))).build()
}

/// `gh -- release upload v1 <archive>` with the zip archive under the home directory.
fn upload_zip(bytes: &[u8]) -> Run {
    let dir = home_dir();
    let asset = put(&dir, &format!("{WIN}.zip"), bytes);
    gh_scanned(&["release", "upload", "v1", &asset])
}

fn unreadable_zip(reason: &str) -> String {
    format!("{ARCHIVE} is a zip archive the scan cannot read: {reason}")
}

#[test]
fn release_zip_of_files_and_directories_passes_the_scan() {
    scanner_set();
    let dir = home_dir();
    let bytes = release_zip().build();
    let named = put(&dir, &format!("{WIN}.zip"), &bytes);
    scan_passed(&gh_scanned(&["release", "upload", "v1", &named]));
    // Known by its content: the same archive under another name.
    let unnamed = put(&dir, "tool.bin", &bytes);
    scan_passed(&gh_scanned(&["release", "upload", "v1", &unnamed]));
}

#[test]
fn release_zip_member_breaking_a_rule_is_refused() {
    scanner_set();
    let literal = literal();
    let text = format!("clean\n{literal}\n");
    let token = format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let secret = format!("token = '{token}'\n");
    let cases: Vec<(Vec<u8>, String)> = vec![
        (
            zip(|zip| zip.file(&format!("{WIN}/README.md"), text.as_bytes())),
            format!(
                "{ARCHIVE} member 2 `{WIN}/README.md`, breaks 1 private rule(s): line 2 \
                 private-identifiers;"
            ),
        ),
        (
            zip(|zip| {
                zip.file(
                    &format!("{WIN}/tool.exe"),
                    &pe(true, b"\x90\x90", literal.as_bytes()),
                )
            }),
            format!("{ARCHIVE} member 2 `{WIN}/tool.exe`: artifact breaks "),
        ),
        (
            zip(|zip| {
                zip.file(
                    &format!("{WIN}/tool.exe"),
                    &pe(true, b"\x90\x90", secret.as_bytes()),
                )
            }),
            format!("{ARCHIVE} member 2 `{WIN}/tool.exe`: artifact breaks secrets rule"),
        ),
        (
            zip(|zip| zip.file(&format!("{WIN}/settings.env"), secret.as_bytes())),
            format!("{ARCHIVE} member 2 `{WIN}/settings.env`, breaks secrets rule"),
        ),
        (
            zip(|zip| zip.file(&format!("{WIN}/{literal}.txt"), b"clean\n")),
            format!(
                "{ARCHIVE} the name of member 2, breaks 1 private rule(s): line 1 \
                 private-identifiers;"
            ),
        ),
        (
            zip(|zip| zip.dir(&format!("{WIN}/{literal}/"))),
            format!("{ARCHIVE} the name of member 2, breaks 1 private rule(s)"),
        ),
        (
            zip(|zip| zip.file(&format!("{}/notes.txt", home()), b"clean\n")),
            format!(
                "{ARCHIVE} the name of member 2, breaks 1 private rule(s): line 1 personal-paths;"
            ),
        ),
        (
            {
                let mut zip = release_zip();
                zip.comment = literal.as_bytes().to_vec();
                zip.build()
            },
            format!("{ARCHIVE} the zip archive's comment, breaks 1 private rule(s)"),
        ),
        (
            zip(|zip| {
                zip.entry(
                    ZipEntry::file(&format!("{WIN}/notes.txt"), b"clean\n")
                        .with(|entry| entry.comment = literal.as_bytes().to_vec()),
                )
            }),
            format!("{ARCHIVE} the comment of member 2, breaks 1 private rule(s)"),
        ),
    ];
    for (bytes, message) in cases {
        let run = upload_zip(&bytes);
        refused_with(&run, &message, &literal);
        assert!(!run.stderr.contains(&token), "{}", run.stderr);
    }
}

#[test]
fn release_zip_member_neither_executable_nor_text_is_refused() {
    let nested = release_zip().build();
    for (name, data) in [
        ("blob.bin", &b"\x00\xff\xfe\x00"[..]),
        ("nested.zip", &nested[..]),
    ] {
        refused_with(
            &upload_zip(&zip(|zip| zip.file(&format!("{WIN}/{name}"), data))),
            &format!(
                "{ARCHIVE} member 2 `{WIN}/{name}`, is neither an ELF, Mach-O or PE executable \
                 nor UTF-8 text, so it cannot be scanned"
            ),
            "",
        );
    }
}

#[test]
fn release_zip_entry_that_is_not_a_file_or_directory_is_refused() {
    for (mode, what) in [
        (S_IFLNK | 0o777, "a symbolic link"),
        (S_IFCHR | 0o644, "a character device"),
        (S_IFIFO | 0o644, "a FIFO"),
    ] {
        refused_with(
            &upload_zip(&zip(|zip| {
                zip.entry(
                    ZipEntry::stored(&format!("{WIN}/entry"), b"target")
                        .with(|entry| entry.mode = mode),
                )
            })),
            &format!(
                "{ARCHIVE} member 2 `{WIN}/entry`, is {what}, not a regular file or a directory"
            ),
            "",
        );
    }
    refused_with(
        &upload_zip(&zip(|zip| {
            zip.entry(ZipEntry::dir(&format!("{WIN}/data/")).with(|entry| {
                entry.data = b"clean\n".to_vec();
            }))
        })),
        &format!("{ARCHIVE} member 2 `{WIN}/data/`, is a directory that carries data"),
        "",
    );
    for entry in [
        ZipEntry::file(&format!("{WIN}/file/"), b""),
        ZipEntry::dir(&format!("{WIN}/dir")),
    ] {
        refused_with(
            &upload_zip(&zip(|zip| zip.entry(entry))),
            &unreadable_zip("the name and the type of member 2 disagree"),
            "",
        );
    }
}

#[test]
fn release_zip_member_name_leaving_the_archive_is_refused() {
    for name in ["/etc/tool", "../tool", "a/../../tool", "..", "a/.."] {
        refused_with(
            &upload_zip(&zip(|zip| zip.file(name, b"clean\n"))),
            &format!("{ARCHIVE} member 2 `{name}`, is an absolute path or has a `..` component"),
            "",
        );
    }
    refused_with(
        &upload_zip(&zip(|zip| zip.file("..\\tool", b"clean\n"))),
        &unreadable_zip("the name of member 2 has a backslash"),
        "",
    );
    refused_with(
        &upload_zip(&zip(|zip| zip.file("", b"clean\n"))),
        &format!("{ARCHIVE} member 2, has an empty name"),
        "",
    );
    refused_with(
        &upload_zip(&zip(|zip| {
            zip.entry(ZipEntry::file("tool", b"clean\n").with(|entry| {
                entry.name = b"tool\xff".to_vec();
            }))
        })),
        &format!("{ARCHIVE} member 2, has a name that is not UTF-8 text"),
        "",
    );
}

#[test]
fn release_zip_that_cannot_be_read_is_refused() {
    let clean = release_zip().build();
    let notes = || ZipEntry::file(&format!("{WIN}/notes.txt"), b"clean\n");
    let member = |edit: fn(&mut ZipEntry)| zip(|zip| zip.entry(notes().with(edit)));
    let end = clean.len() - 22;
    let field = |offset: usize, value: &[u8]| {
        let mut bytes = clean.clone();
        bytes[end + offset..end + offset + value.len()].copy_from_slice(value);
        bytes
    };
    let mut second_end = release_zip();
    second_end.comment = clean[end..].to_vec();
    second_end.comment[20..22].copy_from_slice(&0u16.to_le_bytes());
    let gap = zip(|zip| {
        zip.entry(notes().with(|entry| entry.before = b"bytes between members".to_vec()))
    });
    let mut trailing = clean.clone();
    trailing.extend_from_slice(b"trailing text\n");
    let cases: Vec<(Vec<u8>, String)> = vec![
        (
            member(|entry| entry.flags = 0x0001),
            unreadable_zip("member 2 is encrypted"),
        ),
        (
            member(|entry| entry.flags = 0x0041),
            unreadable_zip("member 2 is encrypted"),
        ),
        (
            member(|entry| entry.flags = 0x0008),
            unreadable_zip("member 2 sets general purpose flags the scan does not read"),
        ),
        (
            member(|entry| entry.method = 12),
            unreadable_zip("member 2 uses compression method 12, which the scan does not read"),
        ),
        (
            member(|entry| entry.method = 99),
            unreadable_zip("member 2 uses compression method 99, which the scan does not read"),
        ),
        (
            member(|entry| entry.crc = Some(0x1234_5678)),
            unreadable_zip("the CRC-32 of member 2 does not match its data"),
        ),
        (
            member(|entry| entry.local_name = Some(b"tool-1.0.0/other.txt".to_vec())),
            unreadable_zip(
                "the local header of member 2 does not match its central directory entry",
            ),
        ),
        (
            member(|entry| entry.local_method = Some(0)),
            unreadable_zip(
                "the local header of member 2 does not match its central directory entry",
            ),
        ),
        (
            member(|entry| entry.local_crc = Some(0)),
            unreadable_zip(
                "the local header of member 2 does not match its central directory entry",
            ),
        ),
        (
            member(|entry| entry.local_size = Some(5)),
            unreadable_zip(
                "the local header of member 2 does not match its central directory entry",
            ),
        ),
        (
            member(|entry| entry.extra = b"UT\x05\x00\x03\x00\x60\x7b\x5b".to_vec()),
            unreadable_zip("member 2 carries an extra field, which the scan does not read"),
        ),
        (
            member(|entry| {
                entry.method = 0;
                entry.size = Some(5);
            }),
            unreadable_zip("member 2 unpacks to a size other than its declared size"),
        ),
        (
            member(|entry| entry.size = Some(5)),
            unreadable_zip("member 2 unpacks to a size other than its declared size"),
        ),
        (
            member(|entry| entry.packed = Some(b"\xff\xff\xff\xff".to_vec())),
            unreadable_zip("the deflate stream of member 2 is corrupt or cut short"),
        ),
        (
            member(|entry| {
                // A complete stored deflate block of the data, then one more byte.
                let mut packed = vec![0x01, 0x06, 0x00, 0xf9, 0xff];
                packed.extend_from_slice(b"clean\n");
                packed.push(0);
                entry.packed = Some(packed);
            }),
            unreadable_zip("data follows the deflate stream of member 2"),
        ),
        (
            gap,
            unreadable_zip("the members overlap or leave bytes no zip structure describes"),
        ),
        (
            trailing,
            unreadable_zip("the end of central directory record is missing or ambiguous"),
        ),
        (
            clean[..clean.len() - 1].to_vec(),
            unreadable_zip("the end of central directory record is missing or ambiguous"),
        ),
        (
            second_end.build(),
            unreadable_zip("the end of central directory record is missing or ambiguous"),
        ),
        (
            b"PK\x03\x04 not a zip archive".to_vec(),
            unreadable_zip("the end of central directory record is missing or ambiguous"),
        ),
        (
            field(4, &1u16.to_le_bytes()),
            unreadable_zip("it spans several disks"),
        ),
        (
            field(6, &1u16.to_le_bytes()),
            unreadable_zip("it spans several disks"),
        ),
        (
            field(8, &3u16.to_le_bytes()),
            unreadable_zip("it spans several disks"),
        ),
        (
            field(8, &[0xff, 0xff]),
            unreadable_zip("it is a zip64 archive"),
        ),
        (
            field(16, &[0xff, 0xff, 0xff, 0xff]),
            unreadable_zip("it is a zip64 archive"),
        ),
        (
            {
                let mut bytes = field(8, &3u16.to_le_bytes());
                bytes[end + 10..end + 12].copy_from_slice(&3u16.to_le_bytes());
                bytes
            },
            unreadable_zip("the central directory does not match the end record"),
        ),
    ];
    for (bytes, message) in cases {
        refused_with(&upload_zip(&bytes), &message, "");
    }
    // An archive behind a prefix, a self-extracting one say, is not read as a zip archive.
    let mut prefixed = b"#!/bin/sh\nexit 0\n".to_vec();
    prefixed.extend_from_slice(&clean);
    refused_with(
        &upload_zip(&prefixed),
        &format!("{ARCHIVE} is neither an ELF, Mach-O or PE executable nor UTF-8 text"),
        "",
    );
    // Two central entries naming the same local header: the second member's bytes are the
    // first's.
    let mut twice = Zip::default()
        .file("a.txt", b"clean\n")
        .file("b.txt", b"clean\n")
        .build();
    let central =
        u32::from_le_bytes(twice[twice.len() - 6..twice.len() - 2].try_into().unwrap()) as usize;
    let second = central + 46 + "a.txt".len();
    twice[second + 42..second + 46].copy_from_slice(&0u32.to_le_bytes());
    twice[second + 46..second + 51].copy_from_slice(b"a.txt");
    refused_with(
        &upload_zip(&twice),
        &unreadable_zip("the members overlap or leave bytes no zip structure describes"),
        "",
    );
}

/// A deflate stream of `mebibytes` MiB of 0xff bytes and the CRC-32 of those bytes: one
/// mebibyte is compressed into a byte-aligned block and repeated.
fn deflate_bomb(mebibytes: usize) -> (Vec<u8>, u32) {
    use flate2::{Compress, Compression, Crc, FlushCompress};
    let chunk = vec![0xffu8; 1024 * 1024];
    let mut compress = Compress::new(Compression::fast(), false);
    let mut block = Vec::with_capacity(chunk.len());
    compress
        .compress_vec(&chunk, &mut block, FlushCompress::Full)
        .unwrap();
    assert_eq!(compress.total_in() as usize, chunk.len());
    let mut chunk_crc = Crc::new();
    chunk_crc.update(&chunk);
    let mut crc = Crc::new();
    let mut bytes = Vec::new();
    for _ in 0..mebibytes {
        bytes.extend_from_slice(&block);
        crc.combine(&chunk_crc);
    }
    let mut finish = Compress::new(Compression::fast(), false);
    let mut last = Vec::with_capacity(64);
    finish
        .compress_vec(&[], &mut last, FlushCompress::Finish)
        .unwrap();
    bytes.extend(last);
    (bytes, crc.sum())
}

#[test]
fn release_zip_unpacking_over_the_read_bound_is_refused() {
    let over = unreadable_zip("it unpacks to more than 128 MiB, the most the scan reads");
    let mib = 1024 * 1024;
    let bomb = |name: &str, mebibytes: usize, declared: u32| {
        let (packed, crc) = deflate_bomb(mebibytes);
        ZipEntry::file(name, b"").with(|entry| {
            entry.method = DEFLATED;
            entry.packed = Some(packed);
            entry.crc = Some(crc);
            entry.size = Some(declared);
        })
    };
    // 129 MiB in one member, declared.
    let one = zip(|zip| zip.entry(bomb("blob", 129, 129 * mib as u32)));
    assert!(one.len() < mib, "{}", one.len());
    refused_with(&upload_zip(&one), &over, "");
    // 65 MiB in each of two members: neither alone is over the bound, both are.
    let two = zip(|zip| {
        zip.entry(bomb("a", 65, 65 * mib as u32))
            .entry(bomb("b", 65, 65 * mib as u32))
    });
    refused_with(&upload_zip(&two), &over, "");
    // 129 MiB declared as six bytes: the read stops after the declared size.
    let lying = zip(|zip| zip.entry(bomb("blob", 129, 6)));
    refused_with(
        &upload_zip(&lying),
        &unreadable_zip("member 2 unpacks to a size other than its declared size"),
        "",
    );
}

#[test]
fn release_zip_with_more_members_than_the_bound_is_refused() {
    let directories = |count: usize| {
        let mut zip = Zip::default();
        for i in 0..count {
            zip = zip.dir(&format!("d{i:05}/"));
        }
        zip.build()
    };
    scan_passed(&upload_zip(&directories(10_000)));
    refused_with(
        &upload_zip(&directories(10_001)),
        &unreadable_zip("it holds more than 10000 members, the most the scan reads"),
        "",
    );
}

#[test]
fn release_zip_entries_of_regular_files_without_unix_mode_pass_the_scan() {
    // A zip written on another system carries no unix mode: a name ending in `/` is a
    // directory, any other a regular file.
    scanner_set();
    let bytes = Zip::default()
        .entry(ZipEntry::dir(&format!("{WIN}/")).with(|entry| entry.mode = 0))
        .entry(
            ZipEntry::file(&format!("{WIN}/README.md"), b"# tool\n").with(|entry| entry.mode = 0),
        )
        .build();
    scan_passed(&upload_zip(&bytes));
}
