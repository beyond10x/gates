//! Conformance of `gates.delivery.BotApi` (`ess/domains/delivery.yaml`), the module
//! documentation of `src/protection.rs` and the `## Acceptance` list of
//! `story:api-protection-writes`, row by row from the security review brief.
//!
//! Every run has no bot configuration (`B10X_BOT_CONFIG` names an absent file) and `PATH`
//! names an empty directory, so no `gh` can start and nothing reaches GitHub. Two outcomes:
//!
//! - refused: non-zero exit, stderr states the owner's cause and does not name the absent
//!   bot configuration (the refusal came before the token step);
//! - reaches the token step: stderr names the absent bot configuration.
//!
//! Refused rows run without a policy, so a request the guard admits fails on the policy
//! instead and the case is red. Rows that reach the token step with a body or through
//! `gh` carry a synthetic owner-only policy so the private-rule scan passes.
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

    fn with_policy(mut self) -> Self {
        let path = self.dir.path().join("policy.json");
        let policy = Policy {
            version: 1,
            nonce: "synthetic-policy-nonce-for-review-test-1234".into(),
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
            .env_remove("B10X_GATES_POLICY_GZ")
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

    /// `b10x-gates api --method <m> --path <p> --output <f> [--input <file>]`.
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

    /// `b10x-gates --repo <sandbox> gh -- api <args>`.
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

/// Refused by the guard before the token step, naming `named`.
fn refused(row: &str, run: &Run, named: &str) {
    assert!(!run.ok, "{row}: exited 0\n{}", run.stderr);
    assert!(
        run.stderr.contains(OWNERS),
        "{row}: not refused as the owner's\n{}",
        run.stderr
    );
    assert!(
        !run.stderr.contains(ABSENT_BOT),
        "{row}: reached the token step\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(named),
        "{row}: refusal does not name {named}\n{}",
        run.stderr
    );
}

/// Admitted by the guard: the run went on to the token step.
fn reached_token(row: &str, run: &Run) {
    assert!(!run.ok, "{row}: exited 0\n{}", run.stderr);
    assert!(
        !run.stderr.contains(OWNERS),
        "{row}: refused by the guard\n{}",
        run.stderr
    );
    assert!(
        run.stderr.contains(ABSENT_BOT),
        "{row}: did not reach the token step\n{}",
        run.stderr
    );
}

/// The JSON body `{"query": <query>}` with the first letter of `name` written as a JSON
/// unicode escape. Built at run time: a literal escape in this file's source was decoded
/// to the plain letter by the editing tool once, so the source holds none.
fn escaped_first_letter(query: &str, name: &str) -> Vec<u8> {
    let body = serde_json::json!({ "query": query }).to_string();
    let first = name.chars().next().unwrap();
    let escape = format!("{}u{:04x}", char::from(92u8), u32::from(first));
    body.replacen(name, &format!("{escape}{}", &name[1..]), 1)
        .into_bytes()
}

fn graphql(query: &str) -> Vec<u8> {
    serde_json::json!({ "query": query })
        .to_string()
        .into_bytes()
}

/// REST writes through `b10x-gates api`: refused, the refusal naming the path.
macro_rules! api_refused {
    ($($case:ident => ($method:literal, $path:literal)),* $(,)?) => {$(
        #[test]
        fn $case() {
            let run = Sandbox::new().api($method, $path, None);
            refused(concat!($method, " ", $path), &run, $path);
        }
    )*};
}

mod api_rest_refused {
    use super::{Sandbox, refused};

    api_refused! {
        lower_case_put_on_a_ruleset => ("put", "/repos/example/example/rulesets/1"),
        options_on_a_ruleset => ("OPTIONS", "/repos/example/example/rulesets/1"),
        patch_behind_lower_case_encoded_parent =>
            ("PATCH", "/repos/example/example/x/%2e%2e/rulesets/1"),
        patch_behind_upper_case_encoded_parent =>
            ("PATCH", "/repos/example/example/x/%2E%2E/rulesets/1"),
        put_required_status_check_contexts =>
            ("PUT", "/repos/example/example/branches/main/protection/required_status_checks/contexts"),
        post_enforce_admins_on_a_slashed_branch =>
            ("POST", "/repos/example/example/branches/feature/a/b/protection/enforce_admins"),
        delete_restriction_users =>
            ("DELETE", "/repos/example/example/branches/main/protection/restrictions/users"),
        put_with_encoded_owner_separator => ("PUT", "/repos/example%2Fexample/rulesets/1"),
        put_triple_encoded_segment => ("PUT", "/repos/example/example/%252572ulesets/1"),
        put_encoded_query => ("PUT", "/repos/example/example/rulesets%3Fx=1"),
        put_matrix_parameter => ("PUT", "/repos/example/example/rulesets;v=1"),
        put_repository_id_branch_protection => ("PUT", "/repositories/1/branches/main/protection"),
        put_organization_id_ruleset => ("PUT", "/organizations/1/rulesets/2"),
    }
}

mod api_graphql_refused {
    use super::{Sandbox, graphql, refused};

    #[test]
    fn post_upper_case_graphql_path() {
        let body = graphql(
            "mutation{deleteBranchProtectionRule(input:{branchProtectionRuleId:\"x\"}){clientMutationId}}",
        );
        let run = Sandbox::new().api("POST", "/GraphQL", Some(&body));
        refused("POST /GraphQL", &run, "deleteBranchProtectionRule");
    }

    /// The first letter of the mutation name is the JSON escape `d`; the server's JSON
    /// parser reads `deleteBranchProtectionRule`.
    #[test]
    fn post_mutation_name_behind_a_json_unicode_escape() {
        let owned = super::escaped_first_letter(
            "mutation{deleteBranchProtectionRule(input:{branchProtectionRuleId:\"x\"}){clientMutationId}}",
            "deleteBranchProtectionRule",
        );
        let body = owned.as_slice();
        let parsed: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert!(
            parsed["query"]
                .as_str()
                .unwrap()
                .contains("deleteBranchProtectionRule"),
            "fixture: the escape must decode to the mutation name"
        );
        assert!(
            !String::from_utf8_lossy(body).contains("deleteBranchProtectionRule"),
            "fixture: the raw body must not hold the plain mutation name"
        );
        let run = Sandbox::new().api("POST", "/graphql", Some(body));
        refused("POST /graphql \\u0064", &run, "deleteBranchProtectionRule");
    }

    #[test]
    fn post_mutation_behind_a_graphql_alias() {
        let body =
            graphql("mutation{a: updateRepositoryRuleset(input:{rulesetId:\"x\"}){clientMutationId}}");
        let run = Sandbox::new().api("POST", "/graphql", Some(&body));
        refused("POST /graphql alias", &run, "updateRepositoryRuleset");
    }

    /// The method does not matter for GraphQL; the path carries a query string.
    #[test]
    fn get_graphql_with_query_string() {
        let body = graphql(
            "mutation{createRepositoryRuleset(input:{sourceId:\"x\",name:\"x\",target:BRANCH,rules:[],enforcement:ACTIVE}){clientMutationId}}",
        );
        let run = Sandbox::new().api("GET", "/graphql?x=1", Some(&body));
        refused("GET /graphql?x=1", &run, "createRepositoryRuleset");
    }
}

mod api_reaches_token {
    use super::{Sandbox, graphql, reached_token};

    #[test]
    fn get_a_ruleset() {
        let run = Sandbox::new().api("GET", "/repos/example/example/rulesets/1", None);
        reached_token("GET rulesets/1", &run);
    }

    #[test]
    fn get_rules_for_a_branch() {
        let run = Sandbox::new().api("GET", "/repos/example/example/rules/branches/main", None);
        reached_token("GET rules/branches/main", &run);
    }

    #[test]
    fn put_contents_of_a_file_named_rulesets() {
        let run = Sandbox::new().api("PUT", "/repos/example/example/contents/rulesets.md", None);
        reached_token("PUT contents/rulesets.md", &run);
    }

    #[test]
    fn post_an_issue() {
        let body = serde_json::json!({ "title": "example", "body": "example" })
            .to_string()
            .into_bytes();
        let run = Sandbox::new()
            .with_policy()
            .api("POST", "/repos/example/example/issues", Some(&body));
        reached_token("POST issues", &run);
    }

    #[test]
    fn post_a_graphql_read_of_rulesets() {
        let body = graphql(
            "query{repository(owner:\"example\",name:\"example\"){rulesets(first:1){nodes{id}}}}",
        );
        let run = Sandbox::new()
            .with_policy()
            .api("POST", "/graphql", Some(&body));
        reached_token("POST /graphql read", &run);
    }
}

mod gh_api_refused {
    use super::{Sandbox, refused};

    #[test]
    fn short_method_cluster() {
        let run = Sandbox::new().gh(&["-XPUT", "repos/example/example/rulesets/1"]);
        refused("-XPUT", &run, "argument");
    }

    #[test]
    fn long_method_with_equals_lower_case() {
        let run = Sandbox::new().gh(&[
            "--method=delete",
            "repos/example/example/branches/main/protection",
        ]);
        refused("--method=delete", &run, "argument");
    }

    #[test]
    fn include_and_method_cluster() {
        let run = Sandbox::new().gh(&["-iX", "PATCH", "/repos/example/example/rulesets/1"]);
        refused("-iX PATCH", &run, "argument");
    }

    #[test]
    fn full_url_endpoint() {
        let run = Sandbox::new().gh(&[
            "https://api.github.com/repos/example/example/rulesets/1",
            "-X",
            "PUT",
        ]);
        refused("full URL", &run, "argument");
    }

    #[test]
    fn colon_placeholders() {
        let run = Sandbox::new().gh(&["repos/:owner/:repo/rulesets/1", "-X", "PUT"]);
        refused(":owner/:repo", &run, "argument");
    }

    #[test]
    fn brace_and_colon_branch_placeholders() {
        let run = Sandbox::new().gh(&["repos/{owner}/{repo}/branches/:branch", "-X", "PUT"]);
        refused("{owner}/{repo}/branches/:branch", &run, "argument");
    }

    #[test]
    fn field_file_holding_a_graphql_mutation() {
        let sandbox = Sandbox::new();
        sandbox.file(
            "query.graphql",
            b"mutation{createBranchProtectionRule(input:{repositoryId:\"x\",pattern:\"main\"}){clientMutationId}}",
        );
        let run = sandbox.gh(&["graphql", "-F", "query=@query.graphql"]);
        refused("-F query=@file", &run, "createBranchProtectionRule");
    }

    /// The file is the JSON body; the mutation's first letter is the JSON escape `c`.
    #[test]
    fn input_file_with_mutation_name_behind_a_json_unicode_escape() {
        let sandbox = Sandbox::new();
        let owned = super::escaped_first_letter(
            "mutation{createRepositoryRuleset(input:{sourceId:\"x\",name:\"x\",target:BRANCH,rules:[],enforcement:ACTIVE}){clientMutationId}}",
            "createRepositoryRuleset",
        );
        let body = owned.as_slice();
        let parsed: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert!(
            parsed["query"]
                .as_str()
                .unwrap()
                .contains("createRepositoryRuleset"),
            "fixture: the escape must decode to the mutation name"
        );
        assert!(
            !String::from_utf8_lossy(body).contains("createRepositoryRuleset"),
            "fixture: the raw body must not hold the plain mutation name"
        );
        sandbox.file("request.json", body);
        let run = sandbox.gh(&["graphql", "--input", "request.json"]);
        refused("--input \\u0063", &run, "createRepositoryRuleset");
    }

    /// The contract (story Proposal, `BotApi` outcome `protection-path` with `route == GhApi`,
    /// module doc of `gh_api_refusal`) refuses a protection path through `gh -- api` whatever
    /// the method; reads go through `b10x-gates api --method GET`. The review brief listed
    /// this row as reaching `gh`; the contract governs.
    #[test]
    fn default_get_of_a_protection_path() {
        let run = Sandbox::new().gh(&["repos/example/example/rulesets"]);
        refused("GET via gh", &run, "argument");
    }
}

mod gh_api_reaches_token {
    use super::{Sandbox, reached_token};

    /// `-f/--raw-field` sends `@query.graphql` as literal text (`gh api --help`: "Add a
    /// string parameter"), never the file, so the guard rightly does not read the file and
    /// the request reaches the token step even though the file names a mutation.
    #[test]
    fn raw_field_at_file_is_sent_as_literal_text_and_admitted() {
        let sandbox = Sandbox::new().with_policy();
        sandbox.file(
            "query.graphql",
            b"mutation{createBranchProtectionRule(input:{repositoryId:\"x\",pattern:\"main\"}){clientMutationId}}",
        );
        let run = sandbox.gh(&["graphql", "-f", "query=@query.graphql"]);
        reached_token("-f query=@file (literal, file not sent)", &run);
    }

    /// The token step comes before `gh` is spawned, so naming the absent bot configuration
    /// proves the guard admitted the request.
    #[test]
    fn graphql_viewer_query() {
        let run = Sandbox::new()
            .with_policy()
            .gh(&["graphql", "-f", "query=query{viewer{login}}"]);
        reached_token("graphql viewer", &run);
    }
}
