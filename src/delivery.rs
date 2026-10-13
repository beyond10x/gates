//! Generic GitHub App delivery. Credentials never enter candidate source.
use crate::{
    BOT_EMAIL, BOT_NAME,
    evidence::{self, Receipt},
    git::{Candidate, Git},
    policy::{self, Policy},
    published_merge::{self, AuthenticatedRead},
    scan::Matchers,
};
use anyhow::{Context, Result, bail, ensure};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Method, StatusCode, blocking::Client};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub struct Github {
    client: Client,
    token: String,
}

impl AuthenticatedRead for Github {
    fn get(&self, path: &str) -> Result<Value> {
        self.api(Method::GET, path, None)
    }
}

/// Publication's ancestry gate. Receipt verification and scans remain separate.
pub fn verify_publication(
    git: &Git,
    policy: &Policy,
    repository: &str,
    head: &str,
    api: &impl AuthenticatedRead,
) -> Result<()> {
    published_merge::verify(git, policy, repository, head, api)
}

/// Hooks receive the App credential from `Github::git`. Read it only when a
/// historical merge needs proof; exact direct commits still need no API read.
pub(crate) struct PushEvidence;

impl AuthenticatedRead for PushEvidence {
    fn get(&self, path: &str) -> Result<Value> {
        Github::from_token(
            std::env::var("B10X_BOT_TOKEN").context("authenticated push evidence unavailable")?,
        )?
        .get(path)
    }
}

/// The GitHub reads and the one write `delete-branch` makes, so the guard can be held
/// to its outcomes without a credential.
pub trait RemoteBranches {
    /// A GET; `None` when GitHub answers 404.
    fn read(&self, path: &str) -> Result<Option<Value>>;
    /// A DELETE that succeeded.
    fn delete(&self, path: &str) -> Result<()>;
}

impl RemoteBranches for Github {
    fn read(&self, path: &str) -> Result<Option<Value>> {
        match self.api_response(Method::GET, path, None) {
            Ok((_, value)) => Ok(Some(value)),
            Err(error)
                if error
                    .downcast_ref::<ApiFailure>()
                    .is_some_and(|f| f.status() == StatusCode::NOT_FOUND) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }

    fn delete(&self, path: &str) -> Result<()> {
        self.api_response(Method::DELETE, path, None).map(|_| ())
    }
}

/// `gates.delivery.DeleteBranch` after the argument check: refuse the default branch,
/// an unknown branch, a branch with classic protection enabled or a ruleset beyond the
/// bot-authority rules, a tip that is not an ancestor of the default branch and a tip
/// that moved, then DELETE `refs/heads/<branch>` and nothing else.
/// Returns the line to print. Every segment of every path is percent-encoded, so no
/// name can change which resource is read or deleted.
pub fn delete_remote_branch(
    api: &impl RemoteBranches,
    deletion: &crate::bot_args::BranchDeletion,
) -> Result<String> {
    let repository = &deletion.repository;
    let branch = &deletion.branch;
    let repo_path = format!(
        "/repos/{}",
        repository
            .split('/')
            .map(published_merge::encoded_segment)
            .collect::<Vec<_>>()
            .join("/")
    );
    let encoded = |name: &str| {
        name.split('/')
            .map(published_merge::encoded_segment)
            .collect::<Vec<_>>()
            .join("/")
    };
    let read = |path: &str, what: &str| -> Result<Option<Value>> {
        api.read(path).map_err(|error| {
            anyhow::anyhow!("bot delete-branch could not read {what} of {repository}: {error}")
        })
    };
    let default = read(&repo_path, "the repository")?
        .with_context(|| format!("bot delete-branch: repository {repository} does not exist"))?;
    let default = default["default_branch"]
        .as_str()
        .filter(|d| !d.is_empty())
        .with_context(|| {
            format!("bot delete-branch: GitHub named no default branch for {repository}")
        })?
        .to_string();
    if *branch == default {
        bail!("bot delete-branch refuses the default branch `{branch}` of {repository}");
    }
    let branch_path = format!("{repo_path}/branches/{}", encoded(branch));
    let tip = |answer: Option<Value>| -> Result<(String, bool)> {
        let Some(answer) = answer else {
            bail!("bot delete-branch: remote branch `{branch}` does not exist in {repository}");
        };
        // GitHub answers a renamed branch with its new name; that is another branch.
        let named = answer["name"].as_str().unwrap_or_default();
        if named != branch {
            bail!(
                "bot delete-branch: GitHub answered for `{}`, not `{branch}`; the branch was \
                 renamed or does not exist",
                named.escape_debug()
            );
        }
        let sha = answer["commit"]["sha"]
            .as_str()
            .filter(|s| matches!(s.len(), 40 | 64) && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .with_context(|| format!("bot delete-branch: GitHub named no tip for `{branch}`"))?;
        // Classic branch protection is `protection.enabled`. The top-level `protected`
        // is true for every branch any ruleset covers, the bot-authority ruleset
        // included, so it never decides; rulesets are judged by `rulesets` below.
        let protected = answer["protection"]["enabled"].as_bool().with_context(|| {
            format!(
                "bot delete-branch: GitHub did not say whether classic branch protection is \
                 enabled on `{branch}` (no boolean `protection.enabled` in the branch answer)"
            )
        })?;
        Ok((sha.to_ascii_lowercase(), protected))
    };
    let (first, protected) = tip(read(&branch_path, "the branch")?)?;
    if protected {
        bail!("bot delete-branch refuses the protected branch `{branch}` of {repository}");
    }
    let comparison = read(
        &format!("{repo_path}/compare/{first}...{}", encoded(&default)),
        "the comparison with the default branch",
    )?
    .with_context(|| {
        format!("bot delete-branch: GitHub cannot compare `{branch}` with `{default}`")
    })?;
    let status = comparison["status"].as_str().unwrap_or("missing");
    let base = comparison["merge_base_commit"]["sha"]
        .as_str()
        .unwrap_or_default()
        .to_ascii_lowercase();
    if !matches!(status, "ahead" | "identical") || base != first {
        bail!(
            "bot delete-branch refuses `{branch}`: its tip {first} is not merged into `{default}` \
             (comparison status {}); deleting it would make commits unreachable. For an \
             unmerged branch only, run `b10x-gates api --method DELETE --path \
             {repo_path}/git/refs/heads/{} --output <file>`, admitted only where the policy \
             admits that API write",
            status.escape_debug(),
            encoded(branch)
        );
    }
    rulesets(
        read(
            &format!(
                "{repo_path}/rules/branches/{}?per_page={RULES_PAGE}",
                encoded(branch)
            ),
            "the rules for the branch",
        )?,
        branch,
        repository,
    )?;
    let (second, _) = tip(read(&branch_path, "the branch again")?)?;
    if second != first {
        bail!(
            "bot delete-branch refuses `{branch}`: its tip moved from {first} to {second} while \
             it was checked; run it again"
        );
    }
    api.delete(&format!("{repo_path}/git/refs/heads/{}", encoded(branch)))
        .map_err(|error| {
            anyhow::anyhow!(
                "bot delete-branch: DELETE of refs/heads/{branch} in {repository} failed: {error}"
            )
        })?;
    Ok(format!("deleted {branch} at {first}"))
}

/// Rule types the organization's bot-authority ruleset puts on every branch, plus the
/// naming and message patterns that restrict nothing a deletion touches. Any other
/// type (`required_status_checks`, `pull_request`, …) marks a branch someone protects.
const ADMITTED_RULES: [&str; 9] = [
    "creation",
    "update",
    "deletion",
    "non_fast_forward",
    "commit_author_email_pattern",
    "committer_email_pattern",
    "commit_message_pattern",
    "committer_name_pattern",
    "branch_name_pattern",
];
/// The page size asked of `rules/branches`; a full page may hide another and is refused.
const RULES_PAGE: usize = 100;

/// `gates.delivery.DeleteBranch`'s ruleset refusals. `protection.enabled` reports only
/// classic branch protection, and the App bypasses the rulesets, so they are read here: an
/// answer that is not a JSON array, a rule type outside `ADMITTED_RULES`, or more than
/// the one `deletion` rule the bot-authority ruleset carries is refused.
fn rulesets(answer: Option<Value>, branch: &str, repository: &str) -> Result<()> {
    let Some(rules) = answer.as_ref().and_then(Value::as_array) else {
        bail!(
            "bot delete-branch refuses `{branch}` of {repository}: GitHub did not list the \
             rulesets that apply to it"
        );
    };
    if rules.len() >= RULES_PAGE {
        bail!(
            "bot delete-branch refuses `{branch}` of {repository}: {} or more ruleset rules \
             apply to it, more than one page shows",
            rules.len()
        );
    }
    let mut unadmitted = Vec::new();
    let mut deletions = 0;
    for rule in rules {
        match rule["type"].as_str() {
            Some("deletion") => deletions += 1,
            Some(kind) if ADMITTED_RULES.contains(&kind) => {}
            Some(kind) => unadmitted.push(format!("`{}`", clean(kind, 60))),
            None => unadmitted.push("a rule without a type".into()),
        }
    }
    if !unadmitted.is_empty() {
        unadmitted.sort();
        unadmitted.dedup();
        bail!(
            "bot delete-branch refuses the ruleset-protected branch `{branch}` of \
             {repository}: rulesets apply {} to it",
            unadmitted.join(", ")
        );
    }
    if deletions > 1 {
        bail!(
            "bot delete-branch refuses `{branch}` of {repository}: {deletions} rulesets \
             restrict its deletion, more than the bot's own"
        );
    }
    Ok(())
}

impl Github {
    pub fn gh(&self, root: &Path, args: &[String]) -> Result<()> {
        const SUPPORTED: [&str; 6] = ["release", "pr", "run", "workflow", "api", "repo"];
        let Some(verb) = args.first().filter(|arg| SUPPORTED.contains(&arg.as_str())) else {
            bail!(
                "unsupported GitHub delivery command {}; supported: {}",
                args.first()
                    .map_or_else(|| "(none)".into(), |arg| format!("`{}`", clean(arg, 60))),
                SUPPORTED.join(", ")
            );
        };
        let status = Command::new("gh")
            .current_dir(root)
            .env("GH_TOKEN", &self.token)
            .args(args)
            .status()
            .context("GitHub delivery command could not start")?;
        ensure!(
            status.success(),
            "GitHub delivery command `gh {verb}` failed ({}); its output is above",
            exit(status)
        );
        Ok(())
    }
    pub fn from_token(token: String) -> Result<Self> {
        ensure!(!token.is_empty(), "GitHub token unavailable");
        Ok(Self {
            client: Client::builder()
                .https_only(true)
                .timeout(Duration::from_secs(60))
                .user_agent("b10x-gates")
                .build()?,
            token,
        })
    }

    pub fn bot() -> Result<Self> {
        let config_root = policy::root()?
            .parent()
            .context("configuration root missing")?
            .to_path_buf();
        let config = std::env::var_os("B10X_BOT_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| config_root.join("b10x-bot.json"));
        let key = std::env::var_os("B10X_BOT_KEY")
            .map(PathBuf::from)
            .unwrap_or_else(|| config_root.join("b10x-bot.private-key.pem"));
        let settings: Value = serde_json::from_slice(&policy::protected_read(&config)?)
            .map_err(|_| anyhow::anyhow!("bot configuration invalid"))?;
        let app_id = settings["app_id"]
            .as_str()
            .map(str::to_owned)
            .or_else(|| settings["app_id"].as_u64().map(|v| v.to_string()))
            .context("bot App id unavailable")?;
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        #[derive(Serialize)]
        struct Claims {
            iat: u64,
            exp: u64,
            iss: String,
        }
        let jwt = jsonwebtoken::encode(
            &Header::new(Algorithm::RS256),
            &Claims {
                iat: now - 60,
                exp: now + 540,
                iss: app_id,
            },
            &EncodingKey::from_rsa_pem(&policy::protected_read(&key)?)
                .map_err(|_| anyhow::anyhow!("bot key invalid"))?,
        )?;
        let app = Self::from_token(jwt)?;
        let installations = app.api(Method::GET, "/app/installations", None)?;
        let installation = installations
            .as_array()
            .context("App installations unavailable")?
            .iter()
            .find(|i| i["account"]["login"] == "beyond10x")
            .context("organization App installation unavailable")?;
        let id = installation["id"]
            .as_u64()
            .context("App installation id unavailable")?;
        let minted = app.api(
            Method::POST,
            &format!("/app/installations/{id}/access_tokens"),
            Some(&json!({})),
        )?;
        Self::from_token(
            minted["token"]
                .as_str()
                .context("installation token unavailable")?
                .into(),
        )
    }

    pub fn api(&self, method: Method, path: &str, body: Option<&Value>) -> Result<Value> {
        self.api_response(method, path, body)
            .map(|(_, value)| value)
    }

    /// `api` with the success status. A non-2xx answer is an `ApiFailure`, whose
    /// text is the status alone until `ApiFailure::render` has the matchers.
    pub fn api_response(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value)> {
        ensure!(
            path.starts_with('/') && !path.contains("..") && !path.contains('#'),
            "invalid GitHub API path"
        );
        let mut request = self
            .client
            .request(method, format!("https://api.github.com{path}"))
            .bearer_auth(&self.token)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .map_err(|_| anyhow::anyhow!("GitHub request failed; sensitive response withheld"))?;
        let status = response.status();
        if !status.is_success() {
            // A body that is not small JSON is never kept: it is rendered as status only.
            let body = response
                .bytes()
                .ok()
                .filter(|bytes| bytes.len() <= 64 * 1024)
                .and_then(|bytes| serde_json::from_slice(&bytes).ok());
            return Err(ApiFailure::new(status, body).into());
        }
        // A body that cannot be read after a 2xx is the same as an empty one.
        let bytes = response.bytes().unwrap_or_default();
        success_body(status, &bytes).map(|value| (status, value))
    }

    pub fn git(&self, root: &Path, args: &[String]) -> Result<()> {
        bot_git(root, args, Some(&self.token))
    }

    pub fn publish(
        &self,
        policy: &Policy,
        candidate: &Candidate,
        receipt: &Receipt,
    ) -> Result<String> {
        evidence::verify(policy, candidate, receipt)?;
        let repo = &candidate.binding.repository;
        let observed = self.api(Method::GET, &format!("/repos/{repo}"), None)?;
        ensure!(
            observed["id"].as_u64().map(|id| id.to_string()).as_deref()
                == Some(candidate.binding.repository_id.as_str()),
            "remote repository identity mismatch"
        );
        let summary = serde_json::to_string(receipt)?;
        ensure!(summary.len() < 60_000, "receipt exceeds GitHub check size");
        let result = self.api(
            Method::POST,
            &format!("/repos/{repo}/check-runs"),
            Some(&json!({
                "name":"b10x-gates / local evidence", "head_sha":candidate.binding.head,
                "status":"completed", "conclusion":"success",
                "external_id":crate::digest(summary.as_bytes()),
                "output":{"title":"Signed common-gate receipt", "summary":summary}
            })),
        )?;
        ensure!(
            result["app"]["slug"] == "b10x-bot",
            "receipt check was not published by the bot App"
        );
        Ok(result["html_url"]
            .as_str()
            .context("published check URL missing")?
            .into())
    }

    pub fn receipts(&self, repository: &str, head: &str) -> Result<Vec<Receipt>> {
        let mut receipts = Vec::new();
        for page in 1..=20 {
            let response = self.api(Method::GET, &format!("/repos/{repository}/commits/{head}/check-runs?check_name=b10x-gates%20%2F%20local%20evidence&filter=all&per_page=100&page={page}"), None)?;
            let checks = response["check_runs"]
                .as_array()
                .context("check list invalid")?;
            for check in checks {
                if check["app"]["slug"] == "b10x-bot"
                    && check["head_sha"] == head
                    && check["conclusion"] == "success"
                    && let Some(summary) = check["output"]["summary"].as_str()
                    && let Ok(receipt) = serde_json::from_str(summary)
                {
                    receipts.push(receipt);
                }
            }
            if checks.len() < 100 {
                return Ok(receipts);
            }
        }
        Ok(receipts) // Exhausted search is a cache miss, never an admission.
    }
}

/// Download candidate objects into a fresh bare repository. The event is trusted workflow input.
pub fn ci_candidate(policy: &Policy, event_path: &Path, target: &Path) -> Result<(Git, Candidate)> {
    ci_candidate_from(policy, event_path, target, |repository| {
        format!("https://github.com/{repository}.git")
    })
}

/// `ci_candidate` with the object source supplied, so a test can serve a local
/// repository. Production always passes the GitHub URL of the trusted repository.
#[doc(hidden)]
pub fn ci_candidate_from(
    policy: &Policy,
    event_path: &Path,
    target: &Path,
    remote: impl Fn(&str) -> String,
) -> Result<(Git, Candidate)> {
    let event: Value = serde_json::from_slice(&fs::read(event_path)?)
        .map_err(|_| anyhow::anyhow!("workflow event invalid"))?;
    let repository = event["repository"]["full_name"]
        .as_str()
        .context("event repository missing")?;
    let trusted = policy.repository(repository)?;
    ensure!(
        event["repository"]["id"]
            .as_u64()
            .map(|v| v.to_string())
            .as_deref()
            == Some(trusted.id.as_str()),
        "event repository identity mismatch"
    );
    let (head, mut fetch_ref) = if let Some(pr) = event.get("pull_request") {
        let number = pr["number"]
            .as_u64()
            .or_else(|| event["number"].as_u64())
            .context("PR number missing")?;
        (
            pr["head"]["sha"]
                .as_str()
                .context("PR commit missing")?
                .to_owned(),
            format!("refs/pull/{number}/head"),
        )
    } else if let Some(group) = event.get("merge_group") {
        // The queue's merge commit is what lands on the protected branch, so it is
        // fetched by its exact id and bound like a push of that commit: the scan runs
        // from the policy baseline, and `base_sha` decides nothing, as `before` does
        // not for a push. The `gh-readonly-queue` ref can move; the id cannot.
        let head = group["head_sha"]
            .as_str()
            .context("merge group commit missing")?
            .to_owned();
        (head.clone(), head)
    } else {
        let head = event["after"]
            .as_str()
            .or_else(|| event["inputs"]["head"].as_str())
            .context("push commit missing")?
            .to_owned();
        (head.clone(), head)
    };
    ensure!(crate::git::is_oid(&head), "event must name an exact commit");
    ensure!(!target.exists(), "CI object directory must be new");
    let init = Command::new("git")
        .args(["-c", "init.templateDir=", "init", "--bare", "--quiet"])
        .arg(target)
        .output()?;
    ensure!(init.status.success(), "bare object store creation failed");
    let git = Git::new(target)?;
    let tag = event
        .get("ref")
        .and_then(Value::as_str)
        .filter(|reference| reference.starts_with("refs/tags/"));
    if let Some(tag) = tag {
        ensure!(
            git.command()
                .args(["check-ref-format", tag])
                .output()?
                .status
                .success(),
            "invalid event tag ref"
        );
        fetch_ref = format!("{tag}:{tag}");
    }
    // A private repository serves no objects anonymously, so the workflow token is
    // supplied through the environment rather than argv or a URL: a credential in
    // argv is readable by every process on the runner.
    let mut fetch = git.command();
    if let Ok(token) = std::env::var("GITHUB_TOKEN") {
        let basic = base64(format!("x-access-token:{token}").as_bytes());
        fetch
            .env("GIT_CONFIG_COUNT", "1")
            .env("GIT_CONFIG_KEY_0", "http.https://github.com/.extraheader")
            .env(
                "GIT_CONFIG_VALUE_0",
                format!("AUTHORIZATION: basic {basic}"),
            );
    }
    let fetch = fetch
        .args([
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            &remote(repository),
            &fetch_ref,
            &trusted.baseline,
        ])
        .output()?;
    ensure!(fetch.status.success(), "candidate object fetch failed");
    let head = git.resolve(&format!("{head}^{{commit}}"))?;
    let tags = tag.map(|value| vec![value.to_owned()]).unwrap_or_default();
    let candidate = git.candidate(policy, repository, &head, &tags)?;
    Ok((git, candidate))
}

/// A GitHub answer that was not 2xx. Its text is the status alone; GitHub's own
/// message is shown only by `render`, after the private-rule matchers have read it.
#[derive(Debug)]
pub struct ApiFailure {
    status: StatusCode,
    body: Option<Value>,
}

impl std::fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GitHub operation failed ({}); response withheld",
            self.status
        )
    }
}

impl std::error::Error for ApiFailure {}

/// Longest GitHub message shown, in bytes.
const MESSAGE_LIMIT: usize = 300;

impl ApiFailure {
    fn new(status: StatusCode, body: Option<Value>) -> Self {
        Self { status, body }
    }

    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// For a 4xx with a JSON body: the status, GitHub's `message` and each entry
    /// of `errors`, unless any of it breaks a private rule or carries a personal
    /// path. Everything else, and every refusal without matchers, is status only.
    pub fn render(&self, matchers: Option<&Matchers>) -> String {
        let Some(body) = self.body.as_ref().filter(|_| self.status.is_client_error()) else {
            return self.to_string();
        };
        let mut raw = Vec::new();
        let mut parts = Vec::new();
        if let Some(message) = body["message"].as_str() {
            raw.push(message.to_owned());
            parts.push(clean(message, MESSAGE_LIMIT));
        }
        for entry in body["errors"].as_array().into_iter().flatten().take(10) {
            if let Some(message) = entry.as_str() {
                raw.push(message.to_owned());
                parts.push(clean(message, MESSAGE_LIMIT));
                continue;
            }
            let labels: Vec<_> = ["resource", "field", "code"]
                .into_iter()
                .filter_map(|key| entry[key].as_str())
                .collect();
            let message = entry["message"].as_str().unwrap_or_default();
            raw.extend(labels.iter().map(|v| (*v).to_owned()));
            raw.push(message.to_owned());
            let label = labels
                .iter()
                .map(|v| clean(v, 100))
                .collect::<Vec<_>>()
                .join(" ");
            parts.push(match (label.is_empty(), message.is_empty()) {
                (_, true) => label,
                (true, false) => clean(message, MESSAGE_LIMIT),
                (false, false) => format!("{label}: {}", clean(message, MESSAGE_LIMIT)),
            });
        }
        parts.retain(|part| !part.is_empty());
        if parts.is_empty() {
            return self.to_string();
        }
        let detail = parts.join("; ");
        let Some(matchers) = matchers else {
            return format!(
                "GitHub operation failed ({}); message withheld: trusted policy unavailable",
                self.status
            );
        };
        // Read the whole of every field as well as what is shown, so a cut or a
        // removed control character cannot be what lets a rule through.
        let full = raw.join("\n");
        let cleaned: String = full.chars().filter(|c| !c.is_control()).collect();
        if [full.as_bytes(), cleaned.as_bytes(), detail.as_bytes()]
            .into_iter()
            .any(|text| !matchers.text(text).is_empty())
        {
            return format!(
                "GitHub operation failed ({}); message withheld: it matches a private rule",
                self.status
            );
        }
        format!("GitHub operation failed ({}): {detail}", self.status)
    }
}

/// The value of a 2xx answer. A body that is empty or not JSON is still a write that
/// succeeded, so it is `Null`, never an error a caller would retry; a caller that
/// needs a field fails closed on its absence.
fn success_body(status: StatusCode, bytes: &[u8]) -> Result<Value> {
    debug_assert!(status.is_success());
    Ok(serde_json::from_slice(bytes).unwrap_or(Value::Null))
}

#[doc(hidden)]
pub fn success_body_for_test(status: u16, bytes: &[u8]) -> Result<Value> {
    success_body(StatusCode::from_u16(status).expect("valid status"), bytes)
}

#[doc(hidden)]
pub fn api_failure_for_test(status: u16, body: &[u8], matchers: &Matchers) -> String {
    ApiFailure::new(
        StatusCode::from_u16(status).expect("valid status"),
        serde_json::from_slice(body).ok(),
    )
    .render(Some(matchers))
}

/// What `api` prints once the remote operation succeeded.
pub struct ApiReport {
    pub stdout: String,
    pub stderr: Option<String>,
}

/// A remote write that succeeded is a success, whether or not its local response
/// file could be written. When it could not, stdout says what succeeded and stderr
/// why the response was not kept. The URL is shown only after the matchers read it.
pub fn api_success_report(
    status: u16,
    response: &Value,
    output: &Path,
    written: Result<()>,
    matchers: Option<&Matchers>,
) -> Result<ApiReport> {
    let Err(error) = written else {
        return Ok(ApiReport {
            stdout: "bot API operation completed; response retained locally".into(),
            stderr: None,
        });
    };
    let status =
        StatusCode::from_u16(status).map_or_else(|_| status.to_string(), |s| s.to_string());
    let mut stdout = format!("bot API operation succeeded ({status})");
    if let Some(number) = response["number"].as_u64() {
        stdout.push_str(&format!("; number {number}"));
    }
    if let Some(url) = response["html_url"].as_str() {
        let shown = clean(url, MESSAGE_LIMIT);
        let vetted = shown == url
            && url.starts_with("https://")
            && matchers.is_some_and(|m| m.text(url.as_bytes()).is_empty());
        stdout.push_str(&if vetted {
            format!("; {shown}")
        } else {
            "; URL withheld".into()
        });
    }
    Ok(ApiReport {
        stdout,
        stderr: Some(format!(
            "response not written to {}: {error:#}; the remote operation already succeeded, \
             do not repeat it",
            output.display()
        )),
    })
}

/// Run one bot Git command in `root` with the bot identity and environment.
/// `credential` is the installation token `Github::git` supplies for `push` and
/// `fetch`; without one, the credential variables are not set and nothing that runs
/// here can reach the network as the bot.
pub fn bot_git(root: &Path, args: &[String], credential: Option<&str>) -> Result<()> {
    if args.first().is_some_and(|verb| verb == "delete-branch") {
        bail!(
            "bot delete-branch is not a Git command: it runs through the REST API as \
             `b10x-gates bot --repository <owner>/<repo> -- delete-branch <branch>`, never \
             through Git"
        );
    }
    // The same check `b10x-gates bot` runs before minting, so the two cannot drift.
    crate::bot_args::check(args, None)?;
    if matches!(args[0].as_str(), "merge" | "revert") {
        // No credential enters a merge or revert: neither needs the network.
        return integrate(root, &crate::bot_args::integration(args)?);
    }
    run_bot(root, args, bot_command(root, credential))
}

fn run_bot(root: &Path, args: &[String], mut command: Command) -> Result<()> {
    let status = command.args(args).status().context("bot Git failed")?;
    if status.success() {
        return Ok(());
    }
    let verb = &args[0];
    let nothing_staged = if verb == "commit" && !commit_names_changes(args) {
        index_equals_head(root) && !merge_in_progress(root)
    } else {
        false
    };
    bail!(
        "{}bot Git {verb} failed ({}); Git's and the hooks' output is above",
        if nothing_staged {
            "nothing staged: git add the paths, or name them after --; "
        } else {
            ""
        },
        exit(status)
    )
}

/// `git` in `root` with the bot identity, no global or system configuration, no
/// configuration from the caller's environment and, when a credential is given, the
/// push rewrite and credential helper that use it. `GIT_CONFIG_PARAMETERS` and
/// `GIT_CONFIG_COUNT` would carry what the `-c` refusal forbids in argv, such as a
/// `core.hooksPath` that skips `pre-commit` and `pre-push`; without the count, the
/// `GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>` pairs are never read.
fn bot_command(root: &Path, credential: Option<&str>) -> Command {
    let mut command = Command::new("git");
    command
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_COUNT")
        .env("GIT_AUTHOR_NAME", BOT_NAME)
        .env("GIT_AUTHOR_EMAIL", BOT_EMAIL)
        .env("GIT_COMMITTER_NAME", BOT_NAME)
        .env("GIT_COMMITTER_EMAIL", BOT_EMAIL)
        .args([
            "-c",
            &format!("user.name={BOT_NAME}"),
            "-c",
            &format!("user.email={BOT_EMAIL}"),
        ]);
    if let Some(token) = credential {
        command
            .env("B10X_BOT_TOKEN", token)
            .env("B10X_BOT_PUSH", "1")
            .args([
                "-c",
                "url.https://github.com/.pushInsteadOf=git@github.com:",
                "-c",
                "url.https://github.com/.pushInsteadOf=ssh://git@github.com/",
                "-c",
                "credential.https://github.com.helper=",
                "-c",
                "credential.https://github.com.helper=!f() { echo username=x-access-token; echo \"password=${B10X_BOT_TOKEN}\"; }; f",
            ]);
    }
    command
}

/// The bot environment for a merge or revert: no credential, and, like every bot Git
/// command, no configuration from the caller's environment, so the merge drivers read
/// from the repository's configuration files are every driver Git can run.
fn integration_command(root: &Path) -> Command {
    bot_command(root, None)
}

/// Git's answer in `root`, read in the merge or revert environment.
fn git_output(root: &Path, args: &[&str]) -> Result<String> {
    let output = integration_command(root)
        .args(args)
        .stderr(std::process::Stdio::inherit())
        .output()
        .context("bot Git failed")?;
    ensure!(output.status.success(), "git {} failed", args.join(" "));
    Ok(String::from_utf8(output.stdout)
        .context("git output is not UTF-8")?
        .trim_end_matches('\n')
        .to_string())
}

/// The per-worktree Git directory and the common one, as absolute paths.
fn git_dirs(root: &Path, name: &str) -> Result<(PathBuf, PathBuf)> {
    let dirs = git_output(root, &["rev-parse", "--git-dir", "--git-common-dir"])?;
    let mut dirs = dirs.lines().map(|d| root.join(d));
    let (Some(git_dir), Some(common_dir)) = (dirs.next(), dirs.next()) else {
        bail!("bot {name} cannot locate the Git directory");
    };
    Ok((git_dir, common_dir))
}

/// The repository-state refusals of `gates.delivery.Merge` and `Revert`: a merge
/// driver declared in the repository's own configuration, an operation already in
/// progress and, for a revert, an index that differs from HEAD. The merge or revert
/// runs this before Git does; any other verb passes.
pub fn preflight(root: &Path, args: &[String]) -> Result<()> {
    let verb = match args.first().map(String::as_str) {
        Some("merge") => crate::bot_args::Verb::Merge,
        Some("revert") => crate::bot_args::Verb::Revert,
        _ => return Ok(()),
    };
    let name = verb.name();
    let (git_dir, common_dir) = git_dirs(root, name)?;
    // A revert is a three-way merge too: Git runs the same drivers.
    merge_drivers(root, name, &git_dir, &common_dir)?;
    let in_progress = [
        ("MERGE_HEAD", "merge"),
        ("REVERT_HEAD", "revert"),
        ("CHERRY_PICK_HEAD", "cherry-pick"),
        ("rebase-merge", "rebase"),
        ("rebase-apply", "rebase or am"),
        ("sequencer", "cherry-pick or revert sequence"),
    ]
    .into_iter()
    .find(|(path, _)| git_dir.join(path).exists());
    if let Some((_, operation)) = in_progress {
        bail!("bot {name} refused: {operation} in progress; finish or abort it first");
    }
    if verb == crate::bot_args::Verb::Revert {
        // `git revert --no-commit` reverts against the index as it stands, so a
        // staged change would ride inside the bot's `Revert "…"` commit. Plumbing,
        // so no external diff or text conversion runs.
        let status = integration_command(root)
            .args(["diff-index", "--cached", "--quiet", "HEAD", "--"])
            .status()
            .context("bot Git failed")?;
        match status.code() {
            Some(0) => {}
            Some(1) => bail!(
                "bot revert refused: the index differs from HEAD, and the staged changes \
                 would ride inside the Revert commit; commit them or unstage them \
                 (`git restore --staged <path>`) first"
            ),
            _ => bail!("bot revert refused: the index cannot be compared with HEAD"),
        }
    }
    Ok(())
}

/// Refuse a merge or revert when the repository's own configuration names a merge
/// driver, a command Git would run during the three-way merge. The files are parsed
/// as data, with no include expanded; a file that includes another cannot be read
/// that way and is refused too. A refusal names the file relative to the Git
/// directory, never by its local path.
fn merge_drivers(root: &Path, name: &str, git_dir: &Path, common_dir: &Path) -> Result<()> {
    let mut files = vec![
        (common_dir.join("config"), "`.git/config`"),
        (common_dir.join("config.worktree"), "`.git/config.worktree`"),
    ];
    if git_dir != common_dir {
        files.push((
            git_dir.join("config.worktree"),
            "the worktree's `config.worktree`",
        ));
    }
    let mut drivers = Vec::new();
    for (file, label) in files.iter().filter(|(f, _)| f.is_file()) {
        let read = |pattern: &str| -> Result<Vec<String>> {
            let output = Command::new("git")
                .current_dir(root)
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env_remove("GIT_CONFIG_PARAMETERS")
                .env_remove("GIT_CONFIG_COUNT")
                .arg("config")
                .arg("--file")
                .arg(file)
                .args(["--no-includes", "--name-only", "--get-regexp", pattern])
                .stderr(std::process::Stdio::null())
                .output()
                .context("bot Git failed")?;
            // Exit 1 is "no such key"; anything else is a file Git cannot parse.
            match output.status.code() {
                Some(0) => Ok(String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(String::from)
                    .collect()),
                Some(1) => Ok(Vec::new()),
                _ => bail!("bot {name} refused: {label} cannot be read as Git configuration"),
            }
        };
        if !read(r"^include(if\..*)?\.path$")?.is_empty() {
            bail!(
                "bot {name} refused: {label} includes other configuration, which may name a \
                 merge driver; remove the include to {name} as the bot"
            );
        }
        drivers.extend(read(r"^merge\..+\.driver$")?.into_iter().map(|key| {
            key.strip_prefix("merge.")
                .and_then(|k| k.strip_suffix(".driver"))
                .unwrap_or(&key)
                .to_string()
        }));
    }
    if !drivers.is_empty() {
        bail!(
            "bot {name} refused: the repository configuration names the merge driver {}, a \
             command the {name} would run; remove `merge.<driver>.driver` to {name} as the bot",
            drivers
                .iter()
                .map(|d| format!("`{}`", d.escape_debug()))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    Ok(())
}

/// The full hash of the one commit the revision names, so Git integrates exactly
/// that commit: `FETCH_HEAD` with several for-merge lines names its first only.
fn resolve(root: &Path, name: &str, revision: &str) -> Result<String> {
    let output = integration_command(root)
        .args(["rev-parse", "--verify", "--quiet", "--end-of-options"])
        .arg(format!("{revision}^{{commit}}"))
        .output()
        .context("bot Git failed")?;
    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !output.status.success() || !crate::git::is_oid(&hash) {
        bail!(
            "bot {name} refused: `{}` does not name one commit",
            revision.escape_debug()
        );
    }
    Ok(hash)
}

/// The message `git merge <revision>` would have prepared, for the commit it merges by
/// hash: the same `fmt-merge-msg` input line Git's own merge builds from the name.
fn merge_message(root: &Path, plan: &crate::bot_args::Integration, hash: &str) -> Result<String> {
    use std::io::Write;
    let revision = &plan.revision;
    let full = integration_command(root)
        .args(["rev-parse", "--symbolic-full-name", "--end-of-options"])
        .arg(revision)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|o| o.status.success())
        // Without `--verify`, rev-parse echoes `--end-of-options` before the name.
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .rfind(|l| *l != "--end-of-options")
                .map(String::from)
        })
        .unwrap_or_default();
    let fetched = || -> Option<String> {
        let path = git_output(root, &["rev-parse", "--git-path", "FETCH_HEAD"]).ok()?;
        fs::read_to_string(root.join(path))
            .ok()?
            .lines()
            .find(|line| {
                let mut fields = line.split('\t');
                fields.next() == Some(hash) && fields.next() == Some("")
            })
            .map(String::from)
    };
    let line = if let Some(branch) = full.strip_prefix("refs/heads/") {
        format!("{hash}\t\tbranch '{branch}' of .")
    } else if let Some(branch) = full.strip_prefix("refs/remotes/") {
        format!("{hash}\t\tremote-tracking branch '{branch}' of .")
    } else if let Some(tag) = full.strip_prefix("refs/tags/") {
        format!("{hash}\t\ttag '{tag}'")
    } else if let Some(line) = (full == "FETCH_HEAD").then(fetched).flatten() {
        line
    } else {
        format!("{hash}\t\tcommit '{}'", revision.escape_debug())
    };
    let mut command = integration_command(root);
    command.arg("fmt-merge-msg");
    if let Some(at) = plan.options.iter().position(|o| o == "--into-name") {
        command.arg("--into-name").args(plan.options.get(at + 1));
    }
    let mut child = command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .context("bot Git failed")?;
    child
        .stdin
        .take()
        .context("bot Git failed")?
        .write_all(format!("{line}\n").as_bytes())?;
    let output = child.wait_with_output().context("bot Git failed")?;
    ensure!(output.status.success(), "git fmt-merge-msg failed");
    Ok(String::from_utf8(output.stdout)
        .context("git output is not UTF-8")?
        .trim_end()
        .to_string())
}

/// `gates.delivery.Merge` and `Revert`: refuse what the repository state refuses,
/// resolve the one revision to its commit, run Git's no-commit form on that hash, then
/// commit the result as the bot.
fn integrate(root: &Path, plan: &crate::bot_args::Integration) -> Result<()> {
    use crate::bot_args::Verb;
    let name = plan.verb.name();
    let mut line = vec![name.to_string()];
    line.extend(plan.options.iter().cloned());
    preflight(root, &line)?;
    let hash = resolve(root, name, &plan.revision)?;
    let mut command = integration_command(root);
    command.args(["-c", "merge.renormalize=false", name]);
    command.args(&plan.options);
    match plan.verb {
        Verb::Merge => command.args(["--no-ff", "--no-commit"]),
        Verb::Revert => command.arg("--no-commit"),
    };
    let status = command.arg(&hash).status().context("bot Git failed")?;
    if !status.success() {
        if !git_output(root, &["ls-files", "--unmerged"])?.is_empty() {
            bail!(
                "bot {name} stopped on a conflict, left in the index: resolve it, `git add` the \
                 resolved paths, then run `b10x-gates bot -- commit -F -`; or run \
                 `git {name} --abort`"
            );
        }
        bail!(
            "bot Git {name} failed ({}); Git's output is above",
            exit(status)
        );
    }
    if plan.verb == Verb::Merge && !merge_in_progress(root) {
        // Already up to date: there is nothing to commit.
        return Ok(());
    }
    let mut commit = vec!["commit".to_string()];
    if plan.verb == Verb::Merge {
        // A merge commits every line of MERGE_HEAD as a parent: more than one is an
        // octopus, which the bot never commits.
        let (git_dir, _) = git_dirs(root, name)?;
        let heads = fs::read_to_string(git_dir.join("MERGE_HEAD"))
            .context("bot merge cannot read MERGE_HEAD")?
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        if heads != 1 {
            bail!(
                "bot merge refused to commit: MERGE_HEAD names {heads} commits, and the bot \
                 never commits an octopus merge; run `git merge --abort`"
            );
        }
    }
    if !plan.message.is_empty() {
        commit.extend(plan.message.iter().cloned());
    } else if plan.verb == Verb::Merge {
        commit.extend(["-m".to_string(), merge_message(root, plan, &hash)?]);
    } else {
        commit.push("--no-edit".into());
    }
    crate::bot_args::check(&commit, None)?;
    run_bot(root, &commit, integration_command(root)).with_context(|| {
        format!(
            "the {name} is still in progress: fix what is reported, then run \
             `b10x-gates bot -- commit -F -`; or run `git {name} --abort`"
        )
    })
}

/// Control characters removed and the result cut to `limit` bytes on a character
/// boundary, so a remote message cannot rewrite the terminal or flood it.
fn clean(text: &str, limit: usize) -> String {
    let mut out = String::new();
    for c in text.chars().filter(|c| !c.is_control()) {
        if out.len() + c.len_utf8() > limit {
            break;
        }
        out.push(c);
    }
    out
}

fn exit(status: std::process::ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by a signal".into(),
        |code| format!("exit status {code}"),
    )
}

/// Whether a `commit` names what it commits some other way than the index: a
/// pathspec, with or without `--`, or from a file, `-a`/`--all`, an empty or
/// amended commit, or an interactive selection. Only without any of these can an
/// empty index be the reason Git refused. An argument that is neither an option
/// nor an option's value is a pathspec.
fn commit_names_changes(args: &[String]) -> bool {
    const VALUED_LONG: [&str; 10] = [
        "--message",
        "--file",
        "--author",
        "--date",
        "--reuse-message",
        "--reedit-message",
        "--fixup",
        "--squash",
        "--cleanup",
        "--template",
    ];
    let mut rest = args.iter().skip(1);
    while let Some(arg) = rest.next() {
        let arg = arg.as_str();
        if arg == "--" {
            return rest.next().is_some();
        }
        if matches!(
            arg,
            "--all"
                | "--allow-empty"
                | "--amend"
                | "--patch"
                | "--interactive"
                | "--include"
                | "--only"
        ) || arg.starts_with("--pathspec-from-file")
        {
            return true;
        }
        if VALUED_LONG.contains(&arg) || arg == "--trailer" {
            rest.next();
            continue;
        }
        if let Some(cluster) = arg.strip_prefix('-').filter(|c| !c.starts_with('-')) {
            for (i, c) in cluster.char_indices() {
                if matches!(c, 'a' | 'p' | 'i' | 'o') {
                    return true;
                }
                if matches!(c, 'm' | 'F' | 'C' | 'c' | 't') {
                    if i + 1 == cluster.len() {
                        rest.next();
                    }
                    break;
                }
            }
            continue;
        }
        if !arg.starts_with('-') {
            return true;
        }
    }
    false
}

/// A merge commits the whole index even when its tree equals HEAD, so an index equal
/// to HEAD is not "nothing staged" while one is in progress.
fn merge_in_progress(root: &Path) -> bool {
    Command::new("git")
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_COUNT")
        .args(["rev-parse", "-q", "--verify", "MERGE_HEAD"])
        .stdout(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Asked of Git after it refused, in the same repository, rather than read from
/// its localised message.
fn index_equals_head(root: &Path) -> bool {
    Command::new("git")
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_COUNT")
        .args(["diff", "--cached", "--quiet"])
        .status()
        .is_ok_and(|status| status.success())
}

#[doc(hidden)]
pub fn base64_for_test(bytes: &[u8]) -> String {
    base64(bytes)
}

/// Standard base64, for the one HTTP Basic credential this binary constructs. A
/// dependency is not worth taking for sixteen lines in a security-critical tool.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(ALPHABET[((n >> shift) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
