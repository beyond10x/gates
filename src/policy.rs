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
        let meta = fs::symlink_metadata(path).map_err(|e| unavailable(path, &e))?;
        regular(path, &meta)?;
        let probe = tempfile::tempfile()?;
        let uid = probe.metadata()?.uid();
        ensure!(
            meta.uid() == uid,
            "refusing to change permissions on another user's file: {} is owned by uid {}, \
             this process runs as uid {uid}",
            path.display(),
            meta.uid()
        );
        if meta.permissions().mode() & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(|e| {
                anyhow::anyhow!(
                    "protected file {} could not be narrowed to mode 0600: {}",
                    path.display(),
                    e.kind()
                )
            })?;
        }
    }
    let _ = path;
    Ok(())
}

pub fn protected_read(path: &Path) -> Result<Vec<u8>> {
    let meta = fs::symlink_metadata(path).map_err(|e| unavailable(path, &e))?;
    regular(path, &meta)?;
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
            meta.uid() == uid,
            "protected file {} is owned by uid {}, expected uid {uid}",
            path.display(),
            meta.uid()
        );
        if let Some(user) = user.filter(|v| *v != uid) {
            bail!(
                "protected file {} cannot be trusted: the UID environment variable says uid \
                 {user}, this process runs as uid {uid}",
                path.display()
            );
        }
        let mode = meta.permissions().mode();
        ensure!(
            mode & 0o077 == 0,
            "protected file {path} has mode {:04o}, needs 0600 or stricter (chmod 600 {path})",
            mode & 0o7777,
            path = path.display()
        );
        let parent = path.parent().with_context(|| {
            format!("protected file {} has no parent directory", path.display())
        })?;
        let parent_meta = fs::metadata(parent).map_err(|e| {
            anyhow::anyhow!(
                "protected directory {} unavailable: {}",
                parent.display(),
                cause(&e)
            )
        })?;
        ensure!(
            parent_meta.uid() == uid,
            "protected directory {} is owned by uid {}, expected uid {uid}",
            parent.display(),
            parent_meta.uid()
        );
        let parent_mode = parent_meta.permissions().mode();
        ensure!(
            parent_mode & 0o022 == 0,
            "protected directory {dir} has mode {:04o}, writable by group or others \
             (chmod go-w {dir})",
            parent_mode & 0o7777,
            dir = parent.display()
        );
    }
    let bytes = fs::read(path).map_err(|e| {
        anyhow::anyhow!(
            "protected file {} read failed: {}",
            path.display(),
            cause(&e)
        )
    })?;
    if bytes.len() > 4 * 1024 * 1024 {
        bail!("protected file {} exceeds 4 MiB", path.display());
    }
    Ok(bytes)
}

/// Prepare the directory `path` will be written into: create it if absent, and
/// refuse it when another user could write it. `private_write` runs the same check,
/// so a caller may run it before work whose result must not be lost.
pub fn output_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("output {} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).map_err(|e| {
        anyhow::anyhow!(
            "output directory {} cannot be created: {}",
            parent.display(),
            cause(&e)
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Do not change caller-owned parents; newly created configuration roots are handled by enrollment.
        let mode = fs::metadata(parent)
            .map_err(|e| {
                anyhow::anyhow!(
                    "output directory {} unavailable: {}",
                    parent.display(),
                    cause(&e)
                )
            })?
            .permissions()
            .mode();
        ensure!(
            mode & 0o022 == 0,
            "output directory {dir} has mode {:04o}, writable by another user; needs 0700 \
             (chmod 700 {dir})",
            mode & 0o7777,
            dir = parent.display()
        );
    }
    Ok(())
}

pub fn private_write(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    output_directory(path)?;
    let parent = path.parent().context("output parent missing")?;
    let failed = |e: std::io::Error| {
        anyhow::anyhow!(
            "output {} could not be written: {}",
            path.display(),
            cause(&e)
        )
    };
    let mut file = tempfile::NamedTempFile::new_in(parent).map_err(failed)?;
    file.write_all(bytes).map_err(failed)?;
    file.as_file().sync_all().map_err(failed)?;
    file.persist(path).map_err(|e| {
        anyhow::anyhow!(
            "protected output persist failed: {} could not be replaced: {}",
            path.display(),
            cause(&e.error)
        )
    })?;
    Ok(())
}

/// The I/O error kind alone. The operating system's message can carry a path the
/// caller did not name; the kind cannot.
fn cause(error: &std::io::Error) -> String {
    match error.kind() {
        std::io::ErrorKind::NotFound => "not found".into(),
        kind => kind.to_string(),
    }
}

fn unavailable(path: &Path, error: &std::io::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "protected file {} unavailable: {}",
        path.display(),
        cause(error)
    )
}

fn regular(path: &Path, meta: &fs::Metadata) -> Result<()> {
    let kind = if meta.file_type().is_symlink() {
        "a symlink"
    } else if meta.is_dir() {
        "a directory"
    } else if !meta.is_file() {
        "not a regular file"
    } else {
        return Ok(());
    };
    bail!(
        "protected file {} is {kind}; it must be a regular file",
        path.display()
    )
}
