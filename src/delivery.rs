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
        if status.as_u16() == 204 {
            return Ok((status, Value::Null));
        }
        response
            .json()
            .map(|value| (status, value))
            .map_err(|_| anyhow::anyhow!("GitHub response invalid"))
    }

    pub fn git(&self, root: &Path, args: &[String]) -> Result<()> {
        ensure!(
            args.first()
                .is_some_and(|a| matches!(a.as_str(), "commit" | "tag" | "push" | "fetch")),
            "bot Git command must be commit, tag, push or fetch"
        );
        ensure!(
            !args.iter().any(|a| a == "--no-verify"
                || a == "-n"
                || a == "-c"
                || a.starts_with("--config-env")
                || a.starts_with("--exec")),
            "bot delivery cannot bypass hooks or inject Git configuration"
        );
        let status = Command::new("git").current_dir(root)
            .env("GIT_CONFIG_GLOBAL", "/dev/null").env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_AUTHOR_NAME", BOT_NAME).env("GIT_AUTHOR_EMAIL", BOT_EMAIL)
            .env("GIT_COMMITTER_NAME", BOT_NAME).env("GIT_COMMITTER_EMAIL", BOT_EMAIL)
            .env("B10X_BOT_TOKEN", &self.token).env("B10X_BOT_PUSH", "1")
            .args(["-c", &format!("user.name={BOT_NAME}"), "-c", &format!("user.email={BOT_EMAIL}"),
                "-c", "url.https://github.com/.pushInsteadOf=git@github.com:",
                "-c", "url.https://github.com/.pushInsteadOf=ssh://git@github.com/",
                "-c", "credential.https://github.com.helper=",
                "-c", "credential.https://github.com.helper=!f() { echo username=x-access-token; echo \"password=${B10X_BOT_TOKEN}\"; }; f"])
            .args(args).status().context("bot Git failed")?;
        if status.success() {
            return Ok(());
        }
        let verb = &args[0];
        let nothing_staged = if verb == "commit" && !commit_names_changes(args) {
            index_equals_head(root)
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
/// pathspec after `--` or from a file, `-a`/`--all`, an empty or amended commit,
/// or an interactive selection. Only without any of these can an empty index be
/// the reason Git refused.
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
        }
    }
    false
}

/// Asked of Git after it refused, in the same repository, rather than read from
/// its localised message.
fn index_equals_head(root: &Path) -> bool {
    Command::new("git")
        .current_dir(root)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
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
