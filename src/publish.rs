//! `policy publish`: put the committed policy into the CI secrets `ci` reads
//! (`gates.delivery.PublishPolicy`). Only `origin/main:policy.json` of the policy repository
//! is published, after a fetch, never a working-tree file. Values reach `gh` on standard
//! input, never in argv, and no diagnostic carries a byte of them.
use crate::policy::{self, Policy};
use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// GitHub refuses a secret of 48 KB; a value of this many bytes or more is never sent.
pub const SECRET_LIMIT: usize = 48_000;
pub const COMPRESSED_SECRET: &str = "B10X_GATES_POLICY_GZ";
pub const PLAIN_SECRET: &str = "B10X_GATES_POLICY";

/// The targets file: which secrets are written, kept out of code.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    /// The organization whose secrets are written. Default: the one owner of every
    /// repository the policy enrols.
    #[serde(default)]
    pub organization: Option<String>,
    /// Also write the plain `B10X_GATES_POLICY` secrets, for callers on older pins.
    #[serde(default)]
    pub plain: bool,
    /// Repositories whose exceptions leave the organization's plain secret and go to a
    /// repository secret of their own (requires `plain`).
    #[serde(default)]
    pub sliced: Vec<String>,
}

pub struct Options {
    pub repository: PathBuf,
    pub targets: Option<PathBuf>,
    pub marker: Option<PathBuf>,
    pub apply: bool,
    pub force: bool,
}

/// Where a secret is written.
#[derive(Clone, PartialEq, Eq)]
enum Scope {
    Organization(String),
    Repository(String),
}

struct Secret {
    name: &'static str,
    scope: Scope,
    value: Vec<u8>,
}

impl Secret {
    fn describe(&self) -> String {
        match &self.scope {
            Scope::Organization(org) => format!("organization {org} secret {}", self.name),
            Scope::Repository(repo) => format!("repository {repo} secret {}", self.name),
        }
    }

    fn scope_args(&self) -> Vec<String> {
        match &self.scope {
            Scope::Organization(org) => vec!["--org".into(), org.clone()],
            Scope::Repository(repo) => vec!["--repo".into(), repo.clone()],
        }
    }
}

/// `$XDG_STATE_HOME/b10x/gates/policy-published`, else under `~/.local/state`.
pub fn default_marker() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".local/state")))
        .context("state home unavailable")?;
    Ok(base.join("b10x/gates/policy-published"))
}

/// `<configuration home>/b10x/gates/publish.json`.
pub fn default_targets() -> Result<PathBuf> {
    Ok(policy::root()?.join("publish.json"))
}

fn git(repository: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repository)
        .arg("--no-replace-objects")
        .args(args)
        .env("GIT_NO_LAZY_FETCH", "1")
        .stdin(Stdio::null())
        .stderr(Stdio::inherit())
        .output()
        .context("git unavailable")?;
    let operation = args.first().copied().unwrap_or("command");
    ensure!(
        output.status.success(),
        "Git {operation} in the policy repository {} failed ({})",
        repository.display(),
        output.status
    );
    Ok(output.stdout)
}

fn load_targets(path: &Path, explicit: bool) -> Result<Targets> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("publish targets {} invalid: {e}", path.display())),
        Err(e) if !explicit && e.kind() == std::io::ErrorKind::NotFound => Ok(Targets {
            organization: None,
            plain: false,
            sliced: vec![],
        }),
        Err(e) => bail!("publish targets {} unreadable: {e}", path.display()),
    }
}

fn organization(targets: &Targets, policy: &Policy) -> Result<String> {
    if let Some(org) = &targets.organization {
        ensure!(
            !org.is_empty() && org.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "publish targets name an invalid organization"
        );
        return Ok(org.clone());
    }
    let mut owners: Vec<&str> = policy
        .repositories
        .keys()
        .filter_map(|r| r.split_once('/').map(|(owner, _)| owner))
        .collect();
    owners.dedup();
    match owners.as_slice() {
        [owner] => Ok((*owner).to_owned()),
        _ => bail!(
            "the policy enrols repositories of {} owners; name the organization in the \
             publish targets (\"organization\")",
            owners.len()
        ),
    }
}

/// The policy JSON with `keep` deciding which exceptions stay, compact.
fn sliced(document: &serde_json::Value, keep: impl Fn(&str) -> bool) -> Result<Vec<u8>> {
    let mut document = document.clone();
    let exceptions = document
        .get_mut("exceptions")
        .and_then(|e| e.as_array_mut())
        .context("policy exceptions missing")?;
    exceptions.retain(|e| {
        e.get("repository")
            .and_then(|r| r.as_str())
            .is_some_and(&keep)
    });
    let bytes = serde_json::to_vec(&document)?;
    Policy::parse(&bytes).map_err(|e| anyhow::anyhow!("a sliced policy does not parse: {e}"))?;
    Ok(bytes)
}

fn compressed(bytes: &[u8]) -> Result<Vec<u8>> {
    use base64::Engine;
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    encoder.write_all(bytes)?;
    let gzip = encoder.finish()?;
    Ok(base64::engine::general_purpose::STANDARD
        .encode(gzip)
        .into_bytes())
}

fn gh(args: &[String], input: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut child = Command::new("gh")
        .args(args)
        .stdin(if input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("gh unavailable")?;
    if let Some(input) = input {
        child
            .stdin
            .take()
            .context("gh standard input unavailable")?
            .write_all(input)?;
    }
    let output = child.wait_with_output()?;
    ensure!(
        output.status.success(),
        "gh {} {} failed ({})",
        args.first().map_or("", String::as_str),
        args.get(1).map_or("", String::as_str),
        output.status
    );
    Ok(output.stdout)
}

pub fn publish(options: &Options) -> Result<()> {
    let repository = &options.repository;
    git(repository, &["fetch", "-q", "origin", "main"])?;
    let tip = String::from_utf8(git(
        repository,
        &["rev-parse", "--verify", "refs/remotes/origin/main^{commit}"],
    )?)?
    .trim()
    .to_owned();
    let commit = String::from_utf8(git(
        repository,
        &["log", "-1", "--format=%H", &tip, "--", "policy.json"],
    )?)?
    .trim()
    .to_owned();
    ensure!(
        crate::git::is_oid(&commit),
        "origin/main of the policy repository has no policy.json"
    );
    let marker = match &options.marker {
        Some(path) => path.clone(),
        None => default_marker()?,
    };
    let last = std::fs::read_to_string(&marker).ok();
    if !options.force && last.as_deref().map(str::trim) == Some(commit.as_str()) {
        println!("unchanged: policy commit {commit} already published");
        return Ok(());
    }
    let bytes = git(repository, &["show", &format!("{tip}:policy.json")])?;
    let policy = Policy::parse(&bytes).map_err(|e| {
        anyhow::anyhow!(
            "origin/main:policy.json of the policy repository is not a Gates policy: {e}"
        )
    })?;
    let document: serde_json::Value = serde_json::from_slice(&bytes)?;
    let (targets_path, explicit) = match &options.targets {
        Some(path) => (path.clone(), true),
        None => (default_targets()?, false),
    };
    let targets = load_targets(&targets_path, explicit)?;
    ensure!(
        targets.plain || targets.sliced.is_empty(),
        "publish targets list sliced repositories without \"plain\": true"
    );
    for repository in &targets.sliced {
        ensure!(
            policy::valid_repository(repository),
            "publish targets name an invalid repository"
        );
        ensure!(
            policy.repositories.contains_key(repository),
            "publish targets slice {repository}, which the policy does not enrol"
        );
    }
    let org = organization(&targets, &policy)?;
    let mut secrets = vec![Secret {
        name: COMPRESSED_SECRET,
        scope: Scope::Organization(org.clone()),
        value: compressed(&serde_json::to_vec(&document)?)?,
    }];
    if targets.plain {
        secrets.push(Secret {
            name: PLAIN_SECRET,
            scope: Scope::Organization(org.clone()),
            value: sliced(&document, |r| !targets.sliced.iter().any(|s| s == r))?,
        });
        for repository in &targets.sliced {
            secrets.push(Secret {
                name: PLAIN_SECRET,
                scope: Scope::Repository(repository.clone()),
                value: sliced(&document, |r| r == repository)?,
            });
        }
    }
    println!("policy commit {commit}");
    for secret in &secrets {
        println!("{}: {} bytes", secret.describe(), secret.value.len());
    }
    let oversized: Vec<String> = secrets
        .iter()
        .filter(|s| s.value.len() >= SECRET_LIMIT)
        .map(|s| format!("{} is {} bytes", s.describe(), s.value.len()))
        .collect();
    ensure!(
        oversized.is_empty(),
        "nothing published: a secret must stay under {SECRET_LIMIT} bytes; {}",
        oversized.join("; ")
    );
    if !options.apply {
        println!("dry run: nothing published; --apply writes these secrets");
        return Ok(());
    }
    for secret in &secrets {
        let mut args: Vec<String> = vec!["secret".into(), "set".into(), secret.name.into()];
        args.extend(secret.scope_args());
        if matches!(secret.scope, Scope::Organization(_)) {
            args.extend(["--visibility".into(), "all".into()]);
        }
        gh(&args, Some(&secret.value)).map_err(|e| {
            anyhow::anyhow!(
                "writing {}: {e}; the marker is unchanged",
                secret.describe()
            )
        })?;
    }
    let mut scopes: Vec<&Scope> = vec![];
    for secret in &secrets {
        if !scopes.contains(&&secret.scope) {
            scopes.push(&secret.scope);
        }
    }
    for scope in scopes {
        let probe = Secret {
            name: PLAIN_SECRET,
            scope: scope.clone(),
            value: vec![],
        };
        let mut args: Vec<String> = vec!["secret".into(), "list".into()];
        args.extend(probe.scope_args());
        let listing = String::from_utf8_lossy(&gh(&args, None)?).into_owned();
        for secret in secrets.iter().filter(|s| &s.scope == scope) {
            let line = listing
                .lines()
                .find(|l| l.split_whitespace().next() == Some(secret.name))
                .with_context(|| {
                    format!(
                        "gh secret list does not show {} after it was written (the marker is \
                         unchanged)",
                        secret.describe()
                    )
                })?;
            println!("read back {}: {line}", secret.describe());
        }
    }
    if let Some(parent) = marker.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&marker, format!("{commit}\n"))
        .map_err(|e| anyhow::anyhow!("marker {} unwritable: {e}", marker.display()))?;
    println!("published policy commit {commit}");
    Ok(())
}
