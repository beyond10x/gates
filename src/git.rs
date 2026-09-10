//! Git plumbing only: no checkout, diff drivers, filters or candidate execution.
use crate::{digest, policy::Policy};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const MAX_BLOB: usize = 64 * 1024 * 1024;
const MAX_TOTAL: usize = 256 * 1024 * 1024;

/// Compare raw Git identity bytes, without mailmap or display-name normalization.
pub fn exact_identity(value: &[u8], name: &str, email: &str) -> bool {
    let prefix = format!("{name} <{email}> ");
    let Some(date) = value.strip_prefix(prefix.as_bytes()) else {
        return false;
    };
    let Some(space) = date.iter().position(|b| *b == b' ') else {
        return false;
    };
    let (timestamp, zone) = (&date[..space], &date[space + 1..]);
    !timestamp.is_empty()
        && timestamp.iter().all(u8::is_ascii_digit)
        && zone.len() == 5
        && matches!(zone[0], b'+' | b'-')
        && zone[1..].iter().all(u8::is_ascii_digit)
}

fn verify_automation_author(raw: &[u8]) -> Result<()> {
    let mut authors = raw
        .split(|b| *b == b'\n')
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.strip_prefix(b"author "));
    let author = authors.next().context("commit author missing")?;
    ensure!(authors.next().is_none(), "duplicate commit author refused");
    ensure!(
        exact_identity(author, crate::BOT_NAME, crate::BOT_EMAIL)
            || exact_identity(author, crate::ACTIONS_NAME, crate::ACTIONS_EMAIL),
        "commit author must be the exact organization bot or GitHub Actions identity"
    );
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub repository: String,
    pub repository_id: String,
    pub baseline: String,
    pub head: String,
    pub commits: Vec<String>,
    pub tags: Vec<String>,
    pub objects_digest: String,
}

#[derive(Clone)]
pub struct Unit {
    pub location: String,
    pub bytes: Vec<u8>,
    pub workflow: bool,
}

pub struct Candidate {
    pub binding: Binding,
    pub units: Vec<Unit>,
}

pub struct Git {
    pub root: PathBuf,
}

pub fn is_oid(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

impl Git {
    pub fn new(root: &Path) -> Result<Self> {
        let git = Self {
            root: root.to_path_buf(),
        };
        ensure!(
            git.text(&["rev-parse", "--is-shallow-repository"])? == "false",
            "shallow history cannot prove an outgoing range"
        );
        for path in ["info/grafts", "shallow"] {
            let held = git.text(&["rev-parse", "--git-path", path])?;
            let path = git.root.join(held);
            ensure!(
                !path.exists() || std::fs::read(path)?.is_empty(),
                "grafted or shallow history refused"
            );
        }
        ensure!(
            std::env::var_os("GIT_SHALLOW_FILE").is_none()
                && std::env::var_os("GIT_GRAFT_FILE").is_none(),
            "virtual history refused"
        );
        Ok(git)
    }

    pub fn command(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(&self.root)
            .arg("--no-replace-objects")
            .args([
                "-c",
                "core.fsmonitor=false",
                "-c",
                "core.attributesFile=/dev/null",
            ])
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::null());
        cmd
    }

    pub fn read(&self, args: &[&str]) -> Result<Vec<u8>> {
        let output = self
            .command()
            .args(args)
            .output()
            .context("Git plumbing failed")?;
        ensure!(output.status.success(), "Git object operation failed");
        ensure!(
            output.stdout.len() <= MAX_TOTAL,
            "Git object output exceeds limit"
        );
        Ok(output.stdout)
    }

    pub fn text(&self, args: &[&str]) -> Result<String> {
        Ok(String::from_utf8(self.read(args)?)
            .context("Git coordinate is not UTF-8")?
            .trim()
            .to_owned())
    }

    pub fn resolve(&self, rev: &str) -> Result<String> {
        let oid = self.text(&["rev-parse", "--verify", "--end-of-options", rev])?;
        ensure!(is_oid(&oid), "invalid Git object id");
        Ok(oid)
    }

    pub fn blob(&self, oid: &str) -> Result<Vec<u8>> {
        ensure!(is_oid(oid), "invalid blob id");
        let size: usize = self.text(&["cat-file", "-s", oid])?.parse()?;
        ensure!(
            size <= MAX_BLOB,
            "blob exceeds scan limit; no receipt can be issued"
        );
        self.read(&["cat-file", "blob", oid])
    }

    fn tree(&self, rev: &str) -> Result<BTreeMap<String, (String, String)>> {
        let mut entries = BTreeMap::new();
        for entry in self
            .read(&["ls-tree", "-rz", "--full-tree", rev])?
            .split(|v| *v == 0)
            .filter(|v| !v.is_empty())
        {
            let tab = entry
                .iter()
                .position(|v| *v == b'\t')
                .context("invalid tree entry")?;
            let header = std::str::from_utf8(&entry[..tab])?
                .split_whitespace()
                .collect::<Vec<_>>();
            ensure!(header.len() == 3 && is_oid(header[2]), "invalid tree entry");
            let path = String::from_utf8(entry[tab + 1..].to_vec())
                .context("non-UTF-8 filenames refused")?;
            ensure!(
                header[1] == "blob",
                "submodule content cannot be proved by this gate"
            );
            entries.insert(path, (header[0].to_owned(), header[2].to_owned()));
        }
        Ok(entries)
    }

    fn units(
        &self,
        tree: &BTreeMap<String, (String, String)>,
        old: &BTreeMap<String, (String, String)>,
    ) -> Result<Vec<Unit>> {
        let mut units = Vec::new();
        for (path, (mode, oid)) in tree {
            if old.get(path) == Some(&(mode.clone(), oid.clone())) {
                continue;
            }
            units.push(Unit {
                location: format!("filename:{path}"),
                bytes: path.as_bytes().to_vec(),
                workflow: false,
            });
            let bytes = self.blob(oid)?;
            units.push(Unit {
                location: format!("file:{path}"),
                bytes,
                workflow: path.starts_with(".github/workflows/")
                    && (path.ends_with(".yml") || path.ends_with(".yaml")),
            });
        }
        ensure!(
            units.iter().map(|u| u.bytes.len()).sum::<usize>() <= MAX_TOTAL,
            "candidate exceeds scan limit"
        );
        Ok(units)
    }

    pub fn candidate(
        &self,
        policy: &Policy,
        repository: &str,
        head: &str,
        tag_refs: &[String],
    ) -> Result<Candidate> {
        let repo = policy.repository(repository)?;
        ensure!(is_oid(head), "candidate must be an exact commit");
        ensure!(
            self.text(&["cat-file", "-t", head])? == "commit",
            "candidate is not a commit"
        );
        let status = self
            .command()
            .args(["merge-base", "--is-ancestor", &repo.baseline, head])
            .status()?;
        ensure!(
            status.success(),
            "candidate does not descend from its adoption baseline"
        );
        let mut commits: Vec<String> = self
            .text(&[
                "rev-list",
                "--reverse",
                "--topo-order",
                &format!("{}..{head}", repo.baseline),
            ])?
            .lines()
            .map(str::to_owned)
            .collect();
        commits.retain(|v| !v.is_empty());
        let mut units = Vec::new();
        for commit in &commits {
            ensure!(is_oid(commit), "invalid commit coordinate");
            let raw = self.read(&["cat-file", "commit", commit])?;
            // This admission runs before scans AND before receipt reuse, for every
            // reachable candidate commit, including merged side branches.
            verify_automation_author(&raw)
                .with_context(|| format!("commit {commit} has inadmissible authorship"))?;
            let parent = raw
                .split(|v| *v == b'\n')
                .take_while(|v| !v.is_empty())
                .find_map(|line| line.strip_prefix(b"parent "))
                .map(std::str::from_utf8)
                .transpose()?;
            let old = match parent {
                Some(p) => self.tree(p)?,
                None => BTreeMap::new(),
            };
            units.extend(self.units(&self.tree(commit)?, &old)?);
            units.push(Unit {
                location: format!("commit:{commit}"),
                bytes: raw,
                workflow: false,
            });
        }
        let mut tags = BTreeSet::new();
        for tag in tag_refs {
            let tag = self.text(&[
                "rev-parse",
                "--verify",
                "--symbolic-full-name",
                "--end-of-options",
                tag,
            ])?;
            ensure!(
                tag.starts_with("refs/tags/"),
                "tag evidence requires a named tag ref"
            );
            let mut oid = self.resolve(&tag)?;
            ensure!(
                self.resolve(&format!("{oid}^{{commit}}"))? == head,
                "tag does not point at candidate"
            );
            units.push(Unit {
                location: "tag-ref".into(),
                bytes: tag.as_bytes().to_vec(),
                workflow: false,
            });
            while self.text(&["cat-file", "-t", &oid])? == "tag" {
                ensure!(tags.insert(oid.clone()), "duplicate or cyclic tag");
                let raw = self.read(&["cat-file", "tag", &oid])?;
                let next = raw
                    .split(|v| *v == b'\n')
                    .next()
                    .and_then(|v| v.strip_prefix(b"object "))
                    .context("malformed annotated tag")?;
                let next = std::str::from_utf8(next)?.to_owned();
                units.push(Unit {
                    location: format!("tag:{oid}"),
                    bytes: raw,
                    workflow: false,
                });
                ensure!(is_oid(&next), "invalid nested tag");
                oid = next;
            }
        }
        ensure!(
            units.iter().map(|u| u.bytes.len()).sum::<usize>() <= MAX_TOTAL,
            "candidate exceeds scan limit"
        );
        let manifest: Vec<_> = units
            .iter()
            .map(|u| (&u.location, digest(&u.bytes), u.workflow))
            .collect();
        Ok(Candidate {
            binding: Binding {
                repository: repository.into(),
                repository_id: repo.id.clone(),
                baseline: repo.baseline.clone(),
                head: head.into(),
                commits,
                tags: tags.into_iter().collect(),
                objects_digest: digest(&serde_json::to_vec(&manifest)?),
            },
            units,
        })
    }

    pub fn staged(&self) -> Result<Vec<Unit>> {
        let old = self
            .resolve("HEAD")
            .ok()
            .map(|id| self.tree(&id))
            .transpose()?
            .unwrap_or_default();
        let mut tree = BTreeMap::new();
        for entry in self
            .read(&["ls-files", "--stage", "-z"])?
            .split(|v| *v == 0)
            .filter(|v| !v.is_empty())
        {
            let tab = entry
                .iter()
                .position(|v| *v == b'\t')
                .context("invalid index entry")?;
            let header = std::str::from_utf8(&entry[..tab])?
                .split_whitespace()
                .collect::<Vec<_>>();
            ensure!(
                header.len() == 3 && header[2] == "0" && header[0] != "160000",
                "unmerged index or submodule refused"
            );
            let path = String::from_utf8(entry[tab + 1..].to_vec())
                .context("non-UTF-8 index path refused")?;
            tree.insert(path, (header[0].into(), header[1].into()));
        }
        self.units(&tree, &old)
    }

    pub fn historical(&self, baseline: &str) -> Result<Vec<Unit>> {
        self.units(&self.tree(baseline)?, &BTreeMap::new())
    }

    pub fn verify_bot(&self, commits: &[String]) -> Result<()> {
        for oid in commits {
            let raw = self.read(&["cat-file", "commit", oid])?;
            for field in [b"author ".as_slice(), b"committer ".as_slice()] {
                let value = raw
                    .split(|v| *v == b'\n')
                    .take_while(|v| !v.is_empty())
                    .find_map(|line| line.strip_prefix(field))
                    .context("missing identity")?;
                let identity = format!("{} <{}> ", crate::BOT_NAME, crate::BOT_EMAIL);
                if !value.starts_with(identity.as_bytes()) {
                    bail!("outgoing commit must have the exact bot author and committer");
                }
            }
        }
        Ok(())
    }
}
