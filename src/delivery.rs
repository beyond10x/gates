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
    collections::BTreeMap,
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
#[doc(hidden)]
pub struct PushEvidence;

impl AuthenticatedRead for PushEvidence {
    fn get(&self, path: &str) -> Result<Value> {
        Github::from_token(
            crate::secret_env::required("B10X_BOT_TOKEN")
                .context("authenticated push evidence unavailable")?,
        )?
        .get(path)
    }
}

/// The GitHub reads and the one write `delete-branch` makes, so the guard can be held
/// to its outcomes without a credential.
pub trait RemoteBranches {
    /// A GET; `None` when GitHub answers 404.
    fn read(&self, path: &str) -> Result<Option<Value>>;
    /// Delete `refs/heads/<branch>` of `repository` only while it points at `tip`, one
    /// compare-and-delete the remote decides (`compare_and_delete_branch`).
    fn delete(&self, repository: &str, branch: &str, tip: &str) -> Result<CompareAndDelete>;
}

/// What a compare-and-delete of a branch did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompareAndDelete {
    /// The remote reported the branch deleted at the expected tip.
    Deleted,
    /// The deletion was refused, so the bot deleted nothing, and the branch read again
    /// is not at the expected tip: `Some` is the tip it points at now, `None` that it
    /// no longer exists.
    Moved(Option<String>),
    /// Git ended without reporting what the remote did with the deletion (a lost
    /// connection, a remote that stopped), and the branch read again is not at the
    /// expected tip: `Some` is the tip it points at now, `None` that it no longer
    /// exists, deleted by this push or by another.
    Unknown(Option<String>),
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

    /// GitHub's REST ref deletion takes no expected tip, so the deletion is a Git push
    /// to the repository's GitHub URL. The installation token reaches Git as
    /// `Github::git` passes it for `push`.
    fn delete(&self, repository: &str, branch: &str, tip: &str) -> Result<CompareAndDelete> {
        ensure!(
            crate::bot_args::repository_shaped(repository),
            "`{}` is not <owner>/<repo>",
            repository.escape_debug()
        );
        compare_and_delete_branch(
            &format!("https://github.com/{repository}.git"),
            branch,
            tip,
            Some(&self.token),
        )
    }
}

/// `delete-branch`'s one write, `git push --force-with-lease=refs/heads/<branch>:<tip>
/// -- <remote> :refs/heads/<branch>`. The lease refuses before anything is sent when the
/// remote advertises another tip, and the push carries `tip` as the ref's old object,
/// which the remote compares under its ref lock, so a push that lands after the last
/// read is never deleted with the branch. A deletion the remote did not report deleted
/// reads the branch again (`git ls-remote`) to say where it is now; only a refusal Git
/// reported proves the bot deleted nothing, and without any report the outcome is
/// `Unknown`. Git runs in a new empty repository made without templates, with no Git
/// variable of the caller's environment but its trace destinations
/// (`scratch_environment`), so no hook, configuration, template or remote of the
/// caller's applies, and `credential` reaches Git through `bot_command`: in the
/// environment, read by the credential helper, never in argv or the URL. Public so a
/// test can delete in a local repository.
#[doc(hidden)]
pub fn compare_and_delete_branch(
    remote: &str,
    branch: &str,
    tip: &str,
    credential: Option<&str>,
) -> Result<CompareAndDelete> {
    ensure!(
        full_object_id(tip),
        "`{}` is not a full object id",
        tip.escape_debug()
    );
    ensure!(
        crate::bot_args::branch_to_delete(branch).ok().as_deref() == Some(branch),
        "`{}` is not a branch name",
        branch.escape_debug()
    );
    let reference = format!("refs/heads/{branch}");
    let scratch = tempfile::Builder::new()
        .prefix("b10x-gates-delete-branch-")
        .tempdir()
        .context("no scratch repository for the deletion")?;
    // `GIT_DIR` set, so a repository named by the caller's environment is never used.
    let git = |credential: Option<&str>| {
        let mut command = bot_command(scratch.path(), credential);
        command
            .env("GIT_DIR", scratch.path())
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit());
        scratch_environment(&mut command);
        command
    };
    // `--template=` wins over `GIT_TEMPLATE_DIR` and `init.templateDir`: no hook or
    // configuration is copied in.
    let init = git(None)
        .args(["init", "--bare", "--quiet", "--template="])
        .output()
        .context("Git could not start")?;
    ensure!(
        init.status.success(),
        "the scratch repository for the deletion could not be created"
    );
    let push = git(credential)
        .args(["push", "--porcelain"])
        .arg(format!("--force-with-lease={reference}:{tip}"))
        .arg("--")
        .arg(remote)
        .arg(format!(":{reference}"))
        .output()
        .context("Git could not start")?;
    // Porcelain: `<flag>\t<from>:<to>\t<summary>`, one line for each ref Git learned the
    // outcome of: `-` the remote deleted it, `!` Git or the remote refused it. With no
    // line for the reference, Git ended before it learned what the remote did.
    let reported = String::from_utf8_lossy(&push.stdout)
        .lines()
        .find_map(|line| {
            let mut fields = line.split('\t');
            let flag = fields.next()?;
            let (_, to) = fields.next()?.rsplit_once(':')?;
            (to == reference).then(|| flag.to_string())
        });
    if reported.as_deref() == Some("-") {
        return Ok(CompareAndDelete::Deleted);
    }
    let refused = reported.as_deref() == Some("!");
    let outcome = if refused {
        format!(
            "Git refused the deletion of {reference} ({})",
            exit(push.status)
        )
    } else {
        format!(
            "Git ended ({}) without reporting what the remote did with the deletion of \
             {reference}",
            exit(push.status)
        )
    };
    let listed = git(credential)
        .args(["ls-remote", "--", remote, &reference])
        .output()
        .context("Git could not start")?;
    ensure!(
        listed.status.success(),
        "{outcome}, and the branch could not be read again ({}){}; Git's output is above",
        exit(listed.status),
        if refused {
            ""
        } else {
            ", so whether it is deleted is unknown"
        }
    );
    let mut now = None;
    for line in String::from_utf8_lossy(&listed.stdout).lines() {
        if let Some((id, name)) = line.split_once('\t')
            && name == reference
        {
            ensure!(
                full_object_id(id),
                "Git listed {reference} at `{}`, not an object id",
                clean(id, 80)
            );
            now = Some(id.to_string());
        }
    }
    if now.as_deref() == Some(tip) {
        bail!("{outcome} while it is at {tip}, so it is not deleted; Git's output is above");
    }
    Ok(if refused {
        CompareAndDelete::Moved(now)
    } else {
        CompareAndDelete::Unknown(now)
    })
}

/// The scratch repository's Git takes no `GIT_*` variable of the caller's environment
/// but the ones `command` already sets or removes and Git's trace destinations
/// (`GIT_TRACE*`; `bot_command` removes `GIT_TRACE2_ENV_VARS` and sets
/// `GIT_TRACE_REDACT`), and no `SSH_ASKPASS`. The rest choose the repository, object
/// store, templates, namespace, configuration, transport and TLS settings or programs
/// Git runs, and the scratch push needs none of them. Removing every `GIT_` name rather
/// than a list keeps a variable Git adds later out as well.
fn scratch_environment(command: &mut Command) {
    let named: Vec<std::ffi::OsString> = command
        .get_envs()
        .map(|(name, _)| name.to_os_string())
        .collect();
    for (name, _) in std::env::vars_os() {
        let bytes = name.as_encoded_bytes();
        if bytes.starts_with(b"GIT_") && !bytes.starts_with(b"GIT_TRACE") && !named.contains(&name)
        {
            command.env_remove(&name);
        }
    }
    command.env_remove("SSH_ASKPASS");
}

/// A full SHA-1 or SHA-256 object id in lower case.
fn full_object_id(id: &str) -> bool {
    matches!(id.len(), 40 | 64)
        && id
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// `gates.delivery.DeleteBranch` after the argument check: refuse the default branch,
/// an unknown branch, a branch with classic protection enabled or a ruleset beyond the
/// bot-authority rules, a tip that is not an ancestor of the default branch and a tip
/// that moved, then delete `refs/heads/<branch>` and nothing else, only while it still
/// points at the tip checked; a tip that moved after the last read is kept and named.
/// Returns the line to print. Every segment of every path is percent-encoded, so no
/// name can change which resource is read.
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
    // The `...` separator is percent-encoded: `api_response` refuses any path holding `..`.
    let comparison = read(
        &format!("{repo_path}/compare/{first}%2E%2E%2E{}", encoded(&default)),
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
    // A push between the read above and this deletion is kept: the deletion carries
    // `first`, and the remote deletes only while the branch still points at it.
    let deleted = api.delete(repository, branch, &first).map_err(|error| {
        anyhow::anyhow!(
            "bot delete-branch: deleting refs/heads/{branch} in {repository}: {error:#}"
        )
    })?;
    match deleted {
        CompareAndDelete::Deleted => Ok(format!("deleted {branch} at {first}")),
        CompareAndDelete::Moved(Some(now)) => bail!(
            "bot delete-branch refuses `{branch}`: its tip moved from {first} to {now} after \
             it was checked, so the remote kept it; run it again"
        ),
        CompareAndDelete::Moved(None) => bail!(
            "bot delete-branch: remote branch `{branch}` no longer exists in {repository}; it \
             was at {first} when checked, and the bot deleted nothing"
        ),
        CompareAndDelete::Unknown(Some(now)) => bail!(
            "bot delete-branch: Git ended without reporting what the remote did with the \
             deletion of `{branch}` in {repository}, so its outcome is unknown; the branch now \
             points at {now}, not at {first} as checked; run it again"
        ),
        CompareAndDelete::Unknown(None) => bail!(
            "bot delete-branch: Git ended without reporting what the remote did with the \
             deletion of `{branch}` in {repository}, so its outcome is unknown; the branch no \
             longer exists, deleted by this push or by another; it was at {first} when checked"
        ),
    }
}

/// Rule types the organization's bot-authority ruleset puts on every branch, each once and
/// all from that one ruleset. The same types from a second ruleset are someone else
/// protecting the branch.
const RESTRICTING_RULES: [&str; 4] = ["creation", "update", "deletion", "non_fast_forward"];
/// Naming and message patterns, which restrict nothing a deletion touches and may come
/// from any ruleset. Any type in neither list (`required_status_checks`,
/// `pull_request`, …) marks a branch someone protects.
const PATTERN_RULES: [&str; 5] = [
    "commit_author_email_pattern",
    "committer_email_pattern",
    "commit_message_pattern",
    "committer_name_pattern",
    "branch_name_pattern",
];
/// The page size asked of `rules/branches`; a full page may hide another and is refused.
const RULES_PAGE: usize = 100;

/// `gates.delivery.DeleteBranch`'s ruleset refusals. `protection.enabled` reports only
/// classic branch protection, and the App bypasses the rulesets, so they are read here.
/// Refused, in this order: an answer that is not a JSON array; a rule type in neither
/// `RESTRICTING_RULES` nor `PATTERN_RULES`; a rule whose `ruleset_id` is missing or not a
/// positive integer; more than the one `deletion` rule the bot-authority ruleset carries;
/// any other restricting type more than once; restricting rules from more than one
/// ruleset.
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
    let mut unattributed = Vec::new();
    // Restricting type → the ruleset ids it came from, one entry per rule.
    let mut restricting: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    for rule in rules {
        let kind = rule["type"].as_str();
        match kind {
            Some(kind) if RESTRICTING_RULES.contains(&kind) || PATTERN_RULES.contains(&kind) => {}
            Some(kind) => unadmitted.push(format!("`{}`", clean(kind, 60))),
            None => unadmitted.push("a rule without a type".into()),
        }
        // `as_u64` is `None` for a negative, fractional, string or absent id.
        match (kind, rule["ruleset_id"].as_u64().filter(|id| *id > 0)) {
            (Some(kind), Some(id)) => {
                if let Some(kind) = RESTRICTING_RULES.iter().find(|k| **k == kind) {
                    restricting.entry(kind).or_default().push(id);
                }
            }
            (kind, None) => unattributed.push(kind.map_or_else(
                || "a rule without a type".to_owned(),
                |kind| format!("`{}`", clean(kind, 60)),
            )),
            (None, Some(_)) => {}
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
    if !unattributed.is_empty() {
        unattributed.sort();
        unattributed.dedup();
        bail!(
            "bot delete-branch refuses `{branch}` of {repository}: GitHub did not name the \
             ruleset (a positive `ruleset_id`) of its {} rule(s)",
            unattributed.join(", ")
        );
    }
    let ids = |ids: &[u64]| {
        ids.iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    };
    if let Some(deletions) = restricting.get("deletion").filter(|ids| ids.len() > 1) {
        bail!(
            "bot delete-branch refuses `{branch}` of {repository}: {} rulesets restrict \
             its deletion, more than the bot's own (`deletion` from rulesets {})",
            deletions.len(),
            ids(deletions)
        );
    }
    let repeated: Vec<String> = restricting
        .iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(kind, from)| format!("`{kind}` {} times (rulesets {})", from.len(), ids(from)))
        .collect();
    if !repeated.is_empty() {
        bail!(
            "bot delete-branch refuses `{branch}` of {repository}: the bot-authority ruleset \
             carries each restricting rule once, but rulesets apply {}",
            repeated.join(", ")
        );
    }
    let mut by_ruleset: BTreeMap<u64, Vec<&str>> = BTreeMap::new();
    for (kind, from) in &restricting {
        for id in from {
            by_ruleset.entry(*id).or_default().push(kind);
        }
    }
    if by_ruleset.len() > 1 {
        bail!(
            "bot delete-branch refuses the ruleset-protected branch `{branch}` of \
             {repository}: its restricting rules come from {} rulesets, not only the \
             bot's own: {}",
            by_ruleset.len(),
            by_ruleset
                .iter()
                .map(|(id, kinds)| format!("ruleset {id} ({})", kinds.join(", ")))
                .collect::<Vec<_>>()
                .join("; ")
        );
    }
    Ok(())
}

/// The path guard `Github::api_response` applies before sending anything: an absolute
/// path with no `..` and no `#`. Public so a test double refuses exactly what the real
/// client refuses.
pub fn api_path_admitted(path: &str) -> bool {
    path.starts_with('/') && !path.contains("..") && !path.contains('#')
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
    /// text is the status alone until `ApiFailure::render` has the matchers. A GET that
    /// GitHub answers with a server error is sent again, see `send_once_or_retried`.
    pub fn api_response(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value)> {
        ensure!(api_path_admitted(path), "invalid GitHub API path");
        send_once_or_retried(&method, std::thread::sleep, || {
            self.send(method.clone(), path, body)
        })
    }

    fn send(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
    ) -> Result<(StatusCode, Value)> {
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
    // A pull request's head is fetched by its id: GitHub has served that id while not
    // advertising `refs/pull/<n>/head`. The ref is only the fallback when the id is not
    // served, which a cross-repository pull request may need; the candidate is the id
    // either way.
    let (head, mut fetch_ref, fallback) = if let Some(pr) = event.get("pull_request") {
        let number = pr["number"]
            .as_u64()
            .or_else(|| event["number"].as_u64())
            .context("PR number missing")?;
        let head = pr["head"]["sha"]
            .as_str()
            .context("PR commit missing")?
            .to_owned();
        (head.clone(), head, Some(format!("refs/pull/{number}/head")))
    } else if let Some(group) = event.get("merge_group") {
        // The queue's merge commit is what lands on the protected branch, so it is
        // fetched by its exact id and bound like a push of that commit: the scan runs
        // from the policy baseline, and `base_sha` decides nothing, as `before` does
        // not for a push. The `gh-readonly-queue` ref can move; the id cannot.
        let head = group["head_sha"]
            .as_str()
            .context("merge group commit missing")?
            .to_owned();
        (head.clone(), head, None)
    } else {
        let head = event["after"]
            .as_str()
            .or_else(|| event["inputs"]["head"].as_str())
            .context("push commit missing")?
            .to_owned();
        (head.clone(), head, None)
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
    // A token that is set but not Unicode is refused, not dropped for an anonymous fetch.
    let token = crate::secret_env::optional("GITHUB_TOKEN")?;
    let basic = token
        .as_ref()
        .map(|token| base64(format!("x-access-token:{token}").as_bytes()));
    let source = remote(repository);
    let mut refusals = Vec::new();
    let mut fetched = false;
    for wanted in std::iter::once(&fetch_ref).chain(fallback.as_ref()) {
        let refspecs = [wanted.as_str(), trusted.baseline.as_str()];
        let mut fetch = git.command();
        if let Some(basic) = &basic {
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
                &source,
            ])
            .args(refspecs)
            .output()?;
        if fetch.status.success() {
            fetched = true;
            break;
        }
        refusals.push(fetch_refusal(
            &fetch.stderr,
            &refspecs,
            Matchers::build(policy).ok().as_ref(),
            &[token.as_deref(), basic.as_deref()],
        ));
    }
    // A fallback ref that git served without the head, as after a force-push, leaves the
    // id's refusal as the cause: that refusal is what `ci` reports.
    let kind = git.text(&["cat-file", "-t", &head]).ok();
    ensure!(
        fetched && (kind.is_some() || refusals.is_empty()),
        "candidate object fetch failed: {}",
        refusals.join("; ")
    );
    // The candidate is the pull request's head id, so that id must be a commit: peeling a
    // tag object would bind a commit the event did not name.
    ensure!(
        fallback.is_none() || kind.as_deref() == Some("commit"),
        "event must name an exact commit"
    );
    let head = git.resolve(&format!("{head}^{{commit}}"))?;
    let tags = tag.map(|value| vec![value.to_owned()]).unwrap_or_default();
    let candidate = git.candidate(policy, repository, &head, &tags)?;
    Ok((git, candidate))
}

/// One refused `git fetch`: each of `refspecs` that git's standard error names, and
/// git's last message line. The line is shown only after the credential check and the
/// private-rule matchers have read the whole of git's standard error as well as the
/// line, so a cut or a removed control character cannot be what lets either through.
/// A refspec is named unless it breaks a private rule itself.
fn fetch_refusal(
    stderr: &[u8],
    refspecs: &[&str],
    matchers: Option<&Matchers>,
    secrets: &[Option<&str>],
) -> String {
    let text = String::from_utf8_lossy(stderr);
    let cleaned: String = text.chars().filter(|c| !c.is_control()).collect();
    let shown = |refspecs: &[&str]| {
        refspecs
            .iter()
            .map(|refspec| {
                if matchers.is_some_and(|m| m.text(refspec.as_bytes()).is_empty()) {
                    (*refspec).to_owned()
                } else {
                    "a refspec (withheld)".to_owned()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    // Git names the source side of a refspec; a tag is fetched as `<tag>:<tag>`.
    let named: Vec<&str> = refspecs
        .iter()
        .copied()
        .filter(|refspec| text.contains(refspec.split(':').next().unwrap_or(refspec)))
        .collect();
    let subject = if named.is_empty() {
        format!("git fetch of {} failed", shown(refspecs))
    } else {
        format!("git refused {}", shown(&named))
    };
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .map(|line| clean(line, MESSAGE_LIMIT))
        .unwrap_or_default();
    let message = if line.is_empty() {
        "git printed no message".to_owned()
    } else if secrets
        .iter()
        .flatten()
        .filter(|secret| !secret.is_empty())
        .any(|secret| carries_secret(stderr, secret))
    {
        "git's message withheld: it carries the workflow credential".to_owned()
    } else if let Some(matchers) = matchers {
        if [stderr, cleaned.as_bytes(), line.as_bytes()]
            .into_iter()
            .any(|text| !matchers.text(text).is_empty())
        {
            "git's message withheld: it matches a private rule".to_owned()
        } else {
            line
        }
    } else {
        "git's message withheld: trusted policy unavailable".to_owned()
    };
    format!("{subject}: {message}")
}

/// The longest run of a credential that may appear in a message shown: a longer run of
/// it, or all of a shorter credential, withholds the message.
const SECRET_RUN: usize = 12;

/// Whether `bytes` carry `secret` once every byte outside the secret's own alphabet is
/// removed. Whatever splits it, an invalid byte, a control or a format character, a
/// space, is then gone; a split by a byte of its own alphabet leaves a long run of it.
fn carries_secret(bytes: &[u8], secret: &str) -> bool {
    let secret = secret.as_bytes();
    let mut alphabet = [false; 256];
    for &byte in secret {
        alphabet[usize::from(byte)] = true;
    }
    let reduced: Vec<u8> = bytes
        .iter()
        .copied()
        .filter(|&byte| alphabet[usize::from(byte)])
        .collect();
    let run = secret.len().min(SECRET_RUN);
    secret
        .windows(run)
        .any(|part| reduced.windows(run).any(|window| window == part))
}

/// `fetch_refusal` for a test, with `token` as the workflow credential.
#[doc(hidden)]
pub fn fetch_refusal_for_test(
    stderr: &[u8],
    refspecs: &[&str],
    policy: &Policy,
    token: &str,
) -> String {
    let basic = base64(format!("x-access-token:{token}").as_bytes());
    fetch_refusal(
        stderr,
        refspecs,
        Matchers::build(policy).ok().as_ref(),
        &[Some(token), Some(&basic)],
    )
}

/// How many times a GET is sent in all while GitHub answers it with a server error. On
/// 2026-10-22 `commits/<sha>/pulls` answered 500 for 10 of 23 merges of one repository, to the
/// App and to a personal token alike, and one URL answered 500 four times in a row before 200.
const GET_ATTEMPTS: u32 = 5;
/// The wait before the second attempt; it doubles before each later one (0.5 s to 4 s).
const GET_BACKOFF: Duration = Duration::from_millis(500);

/// Send a request of `method`: a GET through `retry_server_errors`, any other method once.
/// A write that failed with a 5xx may still have happened, so it is never sent again.
fn send_once_or_retried<T>(
    method: &Method,
    sleep: impl FnMut(Duration),
    mut send: impl FnMut() -> Result<T>,
) -> Result<T> {
    if *method == Method::GET {
        return retry_server_errors(sleep, send);
    }
    send()
}

/// Send again while the answer is a 5xx `ApiFailure`, at most `GET_ATTEMPTS` times, and return
/// the last answer. Any other answer or error returns at once. Only GETs come here: a write
/// that failed with a 5xx may still have happened.
fn retry_server_errors<T>(
    mut sleep: impl FnMut(Duration),
    mut send: impl FnMut() -> Result<T>,
) -> Result<T> {
    let mut delay = GET_BACKOFF;
    for _ in 1..GET_ATTEMPTS {
        match send() {
            Err(error) if is_server_error(&error) => {
                sleep(delay);
                delay *= 2;
            }
            answer => return answer,
        }
    }
    send()
}

/// Whether the error is GitHub answering with a 5xx status, under any context or cause.
pub fn is_server_error(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<ApiFailure>()
            .is_some_and(|failure| failure.status().is_server_error())
    })
}

/// A GitHub answer that was not 2xx. Its text is the status alone; GitHub's own
/// message is shown only by `render`, after the private-rule matchers have read it.
#[derive(Debug)]
pub struct ApiFailure {
    status: StatusCode,
    body: Option<Value>,
    /// The path of the GET this answered, when the reader named it.
    read: Option<String>,
}

impl std::fmt::Display for ApiFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(path) = &self.read {
            write!(f, "GET {path}: ")?;
        }
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
    pub fn new(status: StatusCode, body: Option<Value>) -> Self {
        Self {
            status,
            body,
            read: None,
        }
    }

    /// The same answer, its text led by `GET <path>: `, so a refused read stays this
    /// failure to every caller that downcasts to it.
    pub fn answering(mut self, path: &str) -> Self {
        self.read = Some(path.to_owned());
        self
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
            "bot delete-branch is not a Git command the bot passes on: run `b10x-gates bot \
             --repository <owner>/<repo> -- delete-branch <branch>`, which checks the branch \
             through the REST API as the App, then deletes it with a Git push of its own that \
             carries the checked tip"
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

/// Variables of the caller's environment no bot Git process inherits.
/// `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT` would carry what the `-c` refusal
/// forbids in argv, such as a `core.hooksPath` that skips `pre-commit` and `pre-push`;
/// without the count, the `GIT_CONFIG_KEY_<n>`/`GIT_CONFIG_VALUE_<n>` pairs are never
/// read. `GIT_CONFIG` and `GIT_CONFIG_SYSTEM` name other configuration files. The
/// repository, its object store, index and ref namespace are `root`'s, never another
/// named by `GIT_DIR`, `GIT_WORK_TREE`, `GIT_COMMON_DIR`, `GIT_INDEX_FILE`,
/// `GIT_OBJECT_DIRECTORY`, `GIT_ALTERNATE_OBJECT_DIRECTORIES` or `GIT_NAMESPACE`.
/// `GIT_EXEC_PATH` would choose every `git-*` program Git runs, the remote helper that
/// is handed the credential among them, and `GIT_TEMPLATE_DIR` the hooks and
/// configuration a new repository starts with. `GIT_TRACE2_ENV_VARS` names variables
/// whose values Git writes into its trace, `B10X_BOT_TOKEN` among them.
const CALLER_GIT_ENVIRONMENT: [&str; 14] = [
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG",
    "GIT_CONFIG_SYSTEM",
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_NAMESPACE",
    "GIT_EXEC_PATH",
    "GIT_TEMPLATE_DIR",
    "GIT_TRACE2_ENV_VARS",
];

/// The prefix of the caller's variables that set up TLS for Git's HTTP transport; no
/// bot Git process inherits one. `GIT_SSL_NO_VERIFY` turns certificate verification
/// off; `GIT_SSL_CAINFO` and `GIT_SSL_CAPATH` make Git trust whichever authority they
/// name, an interceptor's among them; `GIT_SSL_VERSION` and `GIT_SSL_CIPHER_LIST` admit
/// an older protocol or weaker ciphers; `GIT_SSL_CERT`, `GIT_SSL_KEY`, their `_TYPE`s
/// and `GIT_SSL_CERT_PASSWORD_PROTECTED` offer the remote a client certificate the bot
/// does not use. Removing the prefix rather than a list keeps a variable Git adds
/// later out as well.
const CALLER_TLS_PREFIX: &[u8] = b"GIT_SSL_";

/// `SSLKEYLOGFILE` makes the TLS library Git uses write each session's secrets to the
/// file it names, and they decrypt the request that carries the installation token.
///
/// Kept from the caller: the proxy (`https_proxy`, `GIT_HTTP_PROXY_AUTHMETHOD`,
/// `GIT_PROXY_SSL_*`), which carries Git's own TLS session with the remote through a
/// tunnel and never sees inside it; `GIT_CURL_VERBOSE`, which writes what
/// `GIT_TRACE_CURL` writes, under the redaction `bot_command` forces; and the timing,
/// retry and user-agent settings (`GIT_HTTP_LOW_SPEED_*`, `GIT_HTTP_MAX_*`,
/// `GIT_HTTP_RETRY_AFTER`, `GIT_HTTP_USER_AGENT`).
const CALLER_TLS_KEY_LOG: &str = "SSLKEYLOGFILE";

/// Remove every caller variable of `CALLER_TLS_PREFIX`, and `CALLER_TLS_KEY_LOG`, from
/// `command`'s environment.
fn remove_caller_tls(command: &mut Command) {
    for (name, _) in std::env::vars_os() {
        if name.as_encoded_bytes().starts_with(CALLER_TLS_PREFIX) {
            command.env_remove(&name);
        }
    }
    command.env_remove(CALLER_TLS_KEY_LOG);
}

/// `git` in `root` with the bot identity, no global or system configuration, none of
/// `CALLER_GIT_ENVIRONMENT` or the caller's TLS settings (`remove_caller_tls`), trace
/// redaction on (`GIT_TRACE_REDACT`, so a caller's `GIT_TRACE_CURL` shows no
/// `Authorization` header), certificate verification on (`http.sslVerify`, which wins
/// over the same key in the repository's configuration) and, when a credential is
/// given, the push rewrite and credential helper that use it.
fn bot_command(root: &Path, credential: Option<&str>) -> Command {
    let mut command = Command::new("git");
    command.current_dir(root);
    for name in CALLER_GIT_ENVIRONMENT {
        command.env_remove(name);
    }
    remove_caller_tls(&mut command);
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TRACE_REDACT", "1")
        .env("GIT_AUTHOR_NAME", BOT_NAME)
        .env("GIT_AUTHOR_EMAIL", BOT_EMAIL)
        .env("GIT_COMMITTER_NAME", BOT_NAME)
        .env("GIT_COMMITTER_EMAIL", BOT_EMAIL)
        .args([
            "-c",
            &format!("user.name={BOT_NAME}"),
            "-c",
            &format!("user.email={BOT_EMAIL}"),
            "-c",
            "http.sslVerify=true",
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
/// to HEAD is not "nothing staged" while one is in progress. Asked in the bot's own
/// environment, so of the repository the bot's Git runs in.
fn merge_in_progress(root: &Path) -> bool {
    bot_command(root, None)
        .args(["rev-parse", "-q", "--verify", "MERGE_HEAD"])
        .stdout(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Asked of Git after it refused, in the same repository and environment, rather than
/// read from its localised message.
fn index_equals_head(root: &Path) -> bool {
    bot_command(root, None)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn failure(status: StatusCode) -> anyhow::Error {
        anyhow::Error::from(ApiFailure::new(status, None)).context("GET /repos/o/r")
    }

    /// Run `retry_server_errors` over `answers`, one per attempt; return its result, the
    /// number of sends and the waits it asked for.
    fn run(answers: Vec<Result<u32>>) -> (Result<u32>, usize, Vec<Duration>) {
        let answers = RefCell::new(answers.into_iter());
        let sends = RefCell::new(0);
        let mut waits = Vec::new();
        let result = retry_server_errors(
            |delay| waits.push(delay),
            || {
                *sends.borrow_mut() += 1;
                answers
                    .borrow_mut()
                    .next()
                    .expect("sent more than answered")
            },
        );
        (result, sends.into_inner(), waits)
    }

    #[test]
    fn a_server_error_is_sent_again_until_it_answers() {
        let (result, sends, waits) = run(vec![
            Err(failure(StatusCode::INTERNAL_SERVER_ERROR)),
            Err(failure(StatusCode::BAD_GATEWAY)),
            Ok(7),
        ]);
        assert_eq!(result.unwrap(), 7);
        assert_eq!(sends, 3);
        assert_eq!(
            waits,
            [Duration::from_millis(500), Duration::from_millis(1000)]
        );
    }

    #[test]
    fn retries_are_bounded_and_the_last_server_error_is_returned() {
        let answers = (0..GET_ATTEMPTS + 3)
            .map(|_| Err(failure(StatusCode::INTERNAL_SERVER_ERROR)))
            .collect();
        let (result, sends, waits) = run(answers);
        let error = result.expect_err("a server error that persists must fail");
        assert!(is_server_error(&error));
        assert_eq!(sends, GET_ATTEMPTS as usize);
        assert_eq!(
            waits.iter().sum::<Duration>(),
            Duration::from_millis(7500),
            "{waits:?}"
        );
    }

    #[test]
    fn a_client_error_or_another_error_is_never_sent_again() {
        for error in [
            failure(StatusCode::NOT_FOUND),
            failure(StatusCode::FORBIDDEN),
            failure(StatusCode::TOO_MANY_REQUESTS),
            anyhow::anyhow!("GitHub request failed; sensitive response withheld"),
        ] {
            let (result, sends, waits) = run(vec![Err(error), Ok(1)]);
            assert!(result.is_err());
            assert_eq!((sends, waits.len()), (1, 0));
        }
    }

    /// Run `send_once_or_retried` for `method` over answers that are all 5xx; return the
    /// result, the number of sends and the number of waits.
    fn run_method(method: &Method) -> (Result<u32>, usize, usize) {
        let sends = RefCell::new(0);
        let mut waits = 0;
        let result = send_once_or_retried(
            method,
            |_| waits += 1,
            || {
                *sends.borrow_mut() += 1;
                Err(failure(StatusCode::INTERNAL_SERVER_ERROR))
            },
        );
        (result, sends.into_inner(), waits)
    }

    #[test]
    fn a_write_that_answers_a_server_error_is_sent_once() {
        // A write answered with a 5xx may still have happened, so it is never sent again.
        for method in [
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
        ] {
            let (result, sends, waits) = run_method(&method);
            let error = result.expect_err("a server error must fail");
            assert!(is_server_error(&error), "{method}");
            assert_eq!((sends, waits), (1, 0), "{method}");
        }
    }

    #[test]
    fn a_get_that_answers_a_server_error_is_sent_again() {
        let (result, sends, waits) = run_method(&Method::GET);
        assert!(is_server_error(
            &result.expect_err("a persisting server error must fail")
        ));
        assert_eq!(
            (sends, waits),
            (GET_ATTEMPTS as usize, GET_ATTEMPTS as usize - 1)
        );
    }

    #[test]
    fn a_token_split_by_a_byte_of_its_own_alphabet_is_withheld() {
        // Removing every byte outside the token's alphabet rejoins a token split by an
        // invalid byte or a format character, not one split by a letter: the line shown
        // then carries the token with one byte added. Any long run of it is withheld.
        let token = ["ghs", "_", "synthetic", "Unit", "Token", "ForLocalTest0123"].concat();
        let (left, right) = token.split_at(20);
        let joint = token.chars().next().unwrap();
        let stderr =
            format!("fatal: couldn't find remote ref refs/pull/7/head {left}{joint}{right}\n");
        let shown = fetch_refusal(
            stderr.as_bytes(),
            &["refs/pull/7/head"],
            None,
            &[Some(&token)],
        );
        assert!(!shown.contains(right), "{shown}");
        assert!(
            shown.ends_with("git's message withheld: it carries the workflow credential"),
            "{shown}"
        );
    }
}
