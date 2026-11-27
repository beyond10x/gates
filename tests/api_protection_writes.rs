//! `story:api-protection-writes`, modelled as `gates.delivery.BotApi` in
//! `ess/domains/delivery.yaml`: `b10x-gates api` and `b10x-gates gh -- api` refuse a write
//! to a ruleset or to branch protection before a token is minted.
//!
//! Every run here has no bot configuration (`B10X_BOT_CONFIG` names an absent file) and,
//! unless a case supplies one, no policy, and `PATH` names an empty directory, so no `gh`
//! can run and nothing reaches GitHub. A refusal that names neither the absent bot
//! configuration nor `policy.json` came before the token step and before the policy was
//! read; an error naming the absent bot configuration reached the token step.
use b10x_gates::policy::Policy;
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

#[test]
fn release_assets_under_the_home_directory_pass_the_scan() {
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
            &notes,
            &binary,
            &sums,
        ][..],
        &["release", "create", "v1", &labelled],
        &["release", "create", "v1", &sums, &binary],
        &[
            "release",
            "create",
            "-d",
            "-p",
            "--latest=false",
            "--generate-notes",
            "--title=0.1.32",
            "v1",
            &binary,
        ],
        &["release", "create", "-dpt", "T", "v1", &sums],
        &["release", "create", "-tT", "v1", &sums],
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
            &sums,
        ],
        &[
            "release",
            "upload",
            "v1",
            &binary,
            &sums,
            "--clobber",
            "-R",
            "o/r",
        ],
        &["release", "upload", "v1", &labelled],
        &["release", "upload", "--repo=o/r", "v1", &sums],
        // After `--` every word is positional: the tag first, then assets.
        &["release", "create", "v1", "--", &sums],
        &["release", "upload", "--", "v1", &sums],
        // `--` as the value of `--title` does not end the options.
        &["release", "create", "v1", "--title", "--", &sums],
    ] {
        scan_passed(&gh_scanned(args));
    }
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
    let opaque = put(&dir, "archive.gz", b"\x1f\x8b\x08\x00\xff\xfe\x00");
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
            "argument 4, the asset it names, is neither an ELF executable nor UTF-8 text",
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
            "argument 4, the asset it names, unreadable",
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
