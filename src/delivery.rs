//! Generic GitHub App delivery. Credentials never enter candidate source.
use crate::{
    BOT_EMAIL, BOT_NAME,
    evidence::{self, Receipt},
    git::{Candidate, Git},
    policy::{self, Policy},
};
use anyhow::{Context, Result, ensure};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use reqwest::{Method, blocking::Client};
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

impl Github {
    pub fn gh(&self, root: &Path, args: &[String]) -> Result<()> {
        ensure!(
            args.first().is_some_and(|arg| matches!(
                arg.as_str(),
                "release" | "pr" | "run" | "workflow" | "api" | "repo"
            )),
            "unsupported GitHub delivery command"
        );
        let status = Command::new("gh")
            .current_dir(root)
            .env("GH_TOKEN", &self.token)
            .args(args)
            .status()
            .context("GitHub delivery command could not start")?;
        ensure!(status.success(), "GitHub delivery command failed");
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
        ensure!(
            status.is_success(),
            "GitHub operation failed ({status}); response withheld"
        );
        if status.as_u16() == 204 {
            return Ok(Value::Null);
        }
        response
            .json()
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
        ensure!(status.success(), "bot Git operation refused");
        Ok(())
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
    let fetch = git
        .command()
        .args([
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-recurse-submodules",
            &format!("https://github.com/{repository}.git"),
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
