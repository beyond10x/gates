//! Trusted, owner-only policy. No policy is read from candidate source.
use crate::{RULES, digest};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Repository {
    pub id: String,
    pub baseline: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signer {
    pub public_key: String,
    pub repositories: Vec<String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Exception {
    pub repository: String,
    pub rule: String,
    /// An exact location, or a prefix ending in `*` for a generated or evidence
    /// tree whose file names are not stable.
    pub location: String,
    /// The exact line content the exception admits, or empty for any content at
    /// this location. Empty is for a file regenerated on every build, where no
    /// digest survives the next run.
    pub content_sha256: String,
    /// The exact line, or 0 for any line.
    pub line: usize,
}

impl Exception {
    pub fn covers(&self, repository: &str, rule: &str, location: &str) -> bool {
        self.repository == repository
            && self.rule == rule
            && match self.location.strip_suffix('*') {
                Some(prefix) => !prefix.is_empty() && location.starts_with(prefix),
                None => self.location == location,
            }
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    // Random salt prevents a published digest from serving as a dictionary oracle.
    pub nonce: String,
    pub forbidden_literals: Vec<String>,
    // Regular expressions, for rules a literal cannot express: separator and case
    // variants, a bare surname, a customer name. Compiled case-insensitively.
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
    // Regular expressions whose matched span admits an occurrence inside it, so a real
    // upstream citation need not be falsified. Containment, never line membership.
    #[serde(default)]
    pub allow_patterns: Vec<String>,
    pub repositories: BTreeMap<String, Repository>,
    pub signers: BTreeMap<String, Signer>,
    pub exceptions: Vec<Exception>,
}

impl Policy {
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = protected_read(path)?;
        Self::parse(&bytes)
    }

    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let policy: Self =
            serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("policy format invalid"))?;
        policy.validate()?;
        Ok(policy)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            matches!(self.version, 1 | 2) && self.nonce.len() >= 32,
            "policy version or nonce invalid"
        );
        ensure!(
            !self.forbidden_literals.is_empty() || !self.forbidden_patterns.is_empty(),
            "private policy is empty"
        );
        ensure!(
            self.forbidden_literals
                .iter()
                .all(|v| !v.trim().is_empty() && v.len() >= 3),
            "private rule is empty or too short to be a rule"
        );
        ensure!(
            self.version == 2
                || (self.forbidden_patterns.is_empty() && self.allow_patterns.is_empty()),
            "pattern rules require policy version 2"
        );
        // A policy that cannot compile is refused at load, never at first scan.
        for pattern in self.forbidden_patterns.iter().chain(&self.allow_patterns) {
            ensure!(!pattern.is_empty(), "private rule is empty");
            ensure!(
                regex::bytes::RegexBuilder::new(pattern)
                    .case_insensitive(true)
                    .size_limit(1 << 20)
                    .build()
                    .is_ok(),
                "private rule does not compile"
            );
            // A rule that matches ordinary prose is not a rule: as a forbidden rule
            // it reports every line, as an allowance it admits every occurrence.
            ensure!(
                !crate::scan::matches_everything(pattern),
                "private rule matches everything"
            );
        }
        for pattern in &self.allow_patterns {
            ensure!(
                pattern.contains("(?P<admit>") || pattern.contains("(?<admit>"),
                "an allowance must name what it admits with (?P<admit>...)"
            );
        }
        for (name, repo) in &self.repositories {
            ensure!(
                valid_repository(name)
                    && repo.id.bytes().all(|b| b.is_ascii_digit())
                    && !repo.id.is_empty(),
                "repository identity invalid"
            );
            ensure!(crate::git::is_oid(&repo.baseline), "baseline invalid");
        }
        for exception in &self.exceptions {
            ensure!(
                self.repositories.contains_key(&exception.repository)
                    && RULES.contains(&exception.rule.as_str())
                    && exception.location.len() > 1
                    && exception.location != "*"
                    && matches!(exception.content_sha256.len(), 0 | 64),
                "exception must have an exact rule, repository, location and a digest or none"
            );
        }
        Ok(())
    }

    pub fn repository(&self, name: &str) -> Result<&Repository> {
        self.repositories
            .get(name)
            .context("repository is not enrolled")
    }

    pub fn digest(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self)?))
    }
}

pub fn valid_repository(name: &str) -> bool {
    let parts: Vec<_> = name.split('/').collect();
    parts.len() == 2
        && parts.iter().all(|s| {
            !s.is_empty()
                && !s.starts_with('.')
                && !s.contains("..")
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        })
}

pub fn root() -> Result<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|v| PathBuf::from(v).join(".config")))
        .context("configuration home unavailable")?;
    Ok(base.join("b10x/gates"))
}

/// Narrow a file this user owns to owner-only, so a checkout made with the usual
/// umask satisfies `protected_read`. Git records no mode below the execute bit, so
/// a fresh clone of the policy repository always arrives group- and world-readable.
pub fn protect(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let meta = fs::symlink_metadata(path).context("protected file unavailable")?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "protected file must be a regular file"
        );
        let probe = tempfile::tempfile()?;
        ensure!(
            meta.uid() == probe.metadata()?.uid(),
            "refusing to change permissions on another user's file"
        );
        if meta.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    let _ = path;
    Ok(())
}

pub fn protected_read(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).context("protected file unavailable")?;
    ensure!(
        meta.is_file() && !meta.file_type().is_symlink(),
        "protected file must be a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let user = std::env::var("UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        // Compare ownership with the caller's newly created private file, avoiding unsafe libc.
        let probe = tempfile::tempfile()?;
        let uid = probe.metadata()?.uid();
        ensure!(
            meta.uid() == uid
                && user.is_none_or(|v| v == uid)
                && meta.permissions().mode() & 0o077 == 0,
            "protected file ownership or permissions invalid"
        );
        let parent = path.parent().context("protected file parent missing")?;
        let parent_meta = fs::metadata(parent)?;
        ensure!(
            parent_meta.uid() == uid && parent_meta.permissions().mode() & 0o022 == 0,
            "protected directory is writable by another user"
        );
    }
    let bytes = fs::read(path).context("protected file read failed")?;
    if bytes.len() > 4 * 1024 * 1024 {
        bail!("protected file exceeds limit");
    }
    Ok(bytes)
}

pub fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("output parent missing")?;
    fs::create_dir_all(parent)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Do not change caller-owned parents; newly created configuration roots are handled by enrollment.
        ensure!(
            fs::metadata(parent)?.permissions().mode() & 0o022 == 0,
            "output directory is writable by another user"
        );
    }
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist(path)
        .map_err(|_| anyhow::anyhow!("protected output persist failed"))?;
    Ok(())
}
