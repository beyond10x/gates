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
}

#[test]
fn undecodable_write_path_is_refused() {
    for path in [
        "/repos/example/example/%zz",
        "/repos/example/example/%4",
        "/repos/example/example/%ff",
        "/repos/example/example/%25zz",
    ] {
        let run = Sandbox::new().api("POST", path, None);
        refused(&run, path);
        assert!(run.stderr.contains("cannot be decoded"), "{}", run.stderr);
    }
}

#[test]
fn writes_elsewhere_reach_the_token_step() {
    for path in [
        "/repos/example/example/issues",
        "/repos/example/example/contents/rulesets/protection",
        "/repos/example/example/branches/protection/rename",
        "/repos/rulesets/protection/pulls",
        "/orgs/example/teams",
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

#[test]
fn graphql_mutation_behind_a_json_escape_is_refused() {
    let body =
        br#"{"query":"mutation { updateRepositoryRuleset(input: {}) { clientMutationId } }"}"#;
    refused(
        &Sandbox::new().api("POST", "/graphql", Some(body)),
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
