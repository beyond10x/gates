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
    fn with_policy(mut self) -> Self {
        let path = self.dir.path().join("policy.json");
        let policy = Policy {
            version: 1,
            nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
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
