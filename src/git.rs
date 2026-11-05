//! Git plumbing only: no checkout, diff drivers, filters or candidate execution.
use crate::{digest, policy::Policy};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Read, Write},
    ops::Range,
    path::{Path, PathBuf},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};

const MAX_BLOB: usize = 128 * 1024 * 1024;
/// The most one Git command may print into memory: a tree listing, a commit or a tag object.
/// It bounds one read, not a candidate.
const MAX_OUTPUT: usize = 512 * 1024 * 1024;
/// The most bytes one scan batch holds, each unit counted with its predecessor. A changed
/// file always fits: it and its predecessor are each at most `MAX_BLOB`.
pub const BATCH_LIMIT: usize = 2 * MAX_BLOB;

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

pub(crate) fn unique_header<'a>(raw: &'a [u8], field: &[u8]) -> Result<&'a [u8]> {
    let mut values = raw
        .split(|b| *b == b'\n')
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.strip_prefix(field));
    let value = values.next().context("required commit header missing")?;
    ensure!(values.next().is_none(), "duplicate commit header refused");
    Ok(value)
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
            || exact_identity(author, crate::ACTIONS_NAME, crate::ACTIONS_EMAIL)
            || exact_identity(author, crate::DEPENDABOT_NAME, crate::DEPENDABOT_EMAIL),
        "commit author must be an exact admitted automation identity"
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
    /// The same location's bytes before this change, when it had them. A finding
    /// whose exact line is already present here is inherited, not introduced: a
    /// commit that edits one line of a document is not answerable for the rest of
    /// it. `None` for a new path, a tag, a commit message and the baseline audit.
    pub inherited: Option<Vec<u8>>,
}

/// One unit held by what identifies its bytes rather than by the bytes: they are read, and
/// checked against `digest`, when the unit's batch is scanned.
#[derive(Clone)]
pub struct UnitRef {
    pub location: String,
    pub workflow: bool,
    /// The SHA-256 of the unit's bytes, as `objects_digest` binds it.
    pub digest: String,
    /// The length of the unit's bytes.
    pub length: usize,
    content: Content,
}

#[derive(Clone)]
enum Content {
    /// Bytes no single Git object holds: a filename, a tag ref name, or a unit the caller
    /// built, such as a commit message or an identity.
    Held {
        bytes: Vec<u8>,
        inherited: Option<Vec<u8>>,
    },
    /// A blob, commit or tag object; for a changed file, also the blob it replaced and that
    /// blob's size.
    Object {
        oid: String,
        kind: &'static str,
        predecessor: Option<(String, usize)>,
    },
}

impl UnitRef {
    /// A unit for the object `(oid, kind)`, whose bytes are `bytes`.
    fn object(
        location: String,
        workflow: bool,
        bytes: &[u8],
        (oid, kind): (&str, &'static str),
        predecessor: Option<(String, usize)>,
    ) -> Self {
        Self {
            location,
            workflow,
            digest: digest(bytes),
            length: bytes.len(),
            content: Content::Object {
                oid: oid.to_owned(),
                kind,
                predecessor,
            },
        }
    }

    /// The bytes this unit adds to a batch: its own and its predecessor's.
    pub fn weight(&self) -> usize {
        match &self.content {
            Content::Held { bytes, inherited } => {
                bytes.len() + inherited.as_ref().map_or(0, Vec::len)
            }
            Content::Object { predecessor, .. } => {
                self.length + predecessor.as_ref().map_or(0, |(_, size)| *size)
            }
        }
    }

    /// The unit with its bytes. An object is read through `objects`, opened on first use,
    /// and must be exactly what was bound; any read that fails refuses.
    fn read(&self, objects: &mut Option<Objects>, git: &Git) -> Result<Unit> {
        let (bytes, inherited) = match &self.content {
            Content::Held { bytes, inherited } => (bytes.clone(), inherited.clone()),
            Content::Object {
                oid,
                kind,
                predecessor,
            } => {
                if objects.is_none() {
                    *objects = Some(Objects::open(git)?);
                }
                let objects = objects.as_mut().context("Git cat-file unavailable")?;
                let bytes = objects.object(oid, kind, self.length)?;
                ensure!(
                    bytes.len() == self.length && digest(&bytes) == self.digest,
                    "Git object {oid} differs from the candidate it was bound in"
                );
                let inherited = match predecessor {
                    Some((old, size)) => {
                        let inherited = objects.blob(old, *size)?;
                        ensure!(
                            inherited.len() == *size,
                            "Git object {old} differs from the candidate it was bound in"
                        );
                        Some(inherited)
                    }
                    None => None,
                };
                (bytes, inherited)
            }
        };
        Ok(Unit {
            location: self.location.clone(),
            bytes,
            workflow: self.workflow,
            inherited,
        })
    }
}

impl From<Unit> for UnitRef {
    fn from(unit: Unit) -> Self {
        Self {
            location: unit.location,
            workflow: unit.workflow,
            digest: digest(&unit.bytes),
            length: unit.bytes.len(),
            content: Content::Held {
                bytes: unit.bytes,
                inherited: unit.inherited,
            },
        }
    }
}

/// Units of one object store, read into memory a batch at a time when they are scanned, so
/// the size of the whole is no limit.
#[derive(Clone)]
pub struct Units {
    git: Git,
    entries: Vec<UnitRef>,
}

impl Units {
    /// No units yet, to be read from `git`'s object store.
    pub fn new(git: &Git) -> Self {
        Self {
            git: git.clone(),
            entries: Vec::new(),
        }
    }

    /// Add a unit whose bytes the caller already holds.
    pub fn push(&mut self, unit: Unit) {
        self.entries.push(unit.into());
    }

    pub fn iter(&self) -> std::slice::Iter<'_, UnitRef> {
        self.entries.iter()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The units cut, in order, into consecutive batches each weighing at most the batch
    /// limit. There is always at least one batch, empty when there are no units, so a scan
    /// invokes its scanner as an unbatched one did. A unit heavier than the limit fits no
    /// batch and is refused.
    fn batches(&self) -> Result<Vec<Range<usize>>> {
        let mut batches = Vec::new();
        let (mut start, mut size) = (0, 0);
        for (i, unit) in self.entries.iter().enumerate() {
            let weight = unit.weight();
            ensure!(
                weight <= self.git.batch,
                "unit exceeds the scan batch limit; no receipt can be issued"
            );
            if size + weight > self.git.batch {
                batches.push(start..i);
                (start, size) = (i, 0);
            }
            size += weight;
        }
        batches.push(start..self.entries.len());
        Ok(batches)
    }

    /// Call `scan` with every batch read into memory, in unit order. The batches are cut
    /// before anything is read, and one Git object stream reads them all.
    pub(crate) fn each_batch(&self, mut scan: impl FnMut(&[Unit]) -> Result<()>) -> Result<()> {
        let mut objects = None;
        for batch in self.batches()? {
            let units = self.entries[batch]
                .iter()
                .map(|unit| unit.read(&mut objects, &self.git))
                .collect::<Result<Vec<_>>>()?;
            scan(&units)?;
        }
        Ok(())
    }

    /// Every unit read into memory at once, in order, with no batch limit. For a set known
    /// to be small, and for tests; a scan reads through `each_batch`.
    pub fn read_all(&self) -> Result<Vec<Unit>> {
        let mut objects = None;
        self.entries
            .iter()
            .map(|unit| unit.read(&mut objects, &self.git))
            .collect()
    }
}

impl<'a> IntoIterator for &'a Units {
    type Item = &'a UnitRef;
    type IntoIter = std::slice::Iter<'a, UnitRef>;

    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter()
    }
}

pub struct Candidate {
    pub binding: Binding,
    pub units: Units,
    /// The units of `binding.commits[i]` are `units[spans[i]]`; every unit after the last
    /// span belongs to the candidate's tags.
    pub(crate) spans: Vec<Range<usize>>,
}

impl Candidate {
    /// The units of every commit not in `covered`, then every tag unit, in candidate order,
    /// and how many commits they belong to. Each commit's units were computed against its own
    /// parent, so they are exactly the units a full scan would hand the scanner for it.
    pub(crate) fn units_outside(&self, covered: &BTreeSet<&str>) -> (Units, usize) {
        let mut units = Units::new(&self.units.git);
        let mut commits = 0;
        for (commit, span) in self.binding.commits.iter().zip(&self.spans) {
            if !covered.contains(commit.as_str()) {
                units
                    .entries
                    .extend_from_slice(&self.units.entries[span.clone()]);
                commits += 1;
            }
        }
        let tags = self.spans.last().map_or(0, |span| span.end);
        units.entries.extend_from_slice(&self.units.entries[tags..]);
        (units, commits)
    }
}

/// One long-running `git cat-file --batch-command` answers every object read of a
/// candidate, instead of two processes a blob. A size is read before any content, so the
/// limits refuse without reading an oversized object, and every answer must name the
/// object asked for: a stream that loses its place refuses every later read.
struct Objects {
    child: Child,
    input: Option<ChildStdin>,
    output: BufReader<ChildStdout>,
    broken: bool,
}

impl Objects {
    fn open(git: &Git) -> Result<Self> {
        let mut child = git
            .command()
            .args(["cat-file", "--batch-command"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Git cat-file could not start")?;
        let input = child
            .stdin
            .take()
            .context("Git cat-file input unavailable")?;
        let output = child
            .stdout
            .take()
            .context("Git cat-file output unavailable")?;
        Ok(Self {
            child,
            input: Some(input),
            output: BufReader::new(output),
            broken: false,
        })
    }

    /// Read a blob of at most `limit` bytes. A refusal for size, type or absence leaves the
    /// stream in place; any other failure breaks it for good.
    fn blob(&mut self, oid: &str, limit: usize) -> Result<Vec<u8>> {
        self.object(oid, "blob", limit)
    }

    /// The size a predecessor contributes when it can be inherited from: a blob within the
    /// per-blob limit. An absent, oversized or other object is inherited from by nothing,
    /// so the whole file is answerable, which fails closed; a broken stream refuses.
    fn predecessor(&mut self, oid: &str) -> Result<Option<usize>> {
        match self.info(oid) {
            Ok((kind, size)) => Ok((kind == "blob" && size <= MAX_BLOB).then_some(size)),
            Err(error) if self.broken => Err(error),
            Err(_) => Ok(None),
        }
    }

    fn info(&mut self, oid: &str) -> Result<(String, usize)> {
        ensure!(is_oid(oid), "invalid object id");
        ensure!(
            !self.broken,
            "Git cat-file stream refused after an earlier failure"
        );
        self.ask("info", oid)
    }

    /// Read an object of type `expected` and at most `limit` bytes, with the same refusals
    /// as `blob`.
    fn object(&mut self, oid: &str, expected: &str, limit: usize) -> Result<Vec<u8>> {
        ensure!(is_oid(oid), "invalid {expected} id");
        ensure!(
            !self.broken,
            "Git cat-file stream refused after an earlier failure"
        );
        let (kind, size) = self.ask("info", oid)?;
        ensure!(kind == expected, "Git object {oid} is not a {expected}");
        ensure!(
            size <= limit,
            "{expected} exceeds scan limit; no receipt can be issued"
        );
        let answer = self.ask("contents", oid)?;
        // `ask` marks the stream in place once it has parsed a header; the body is still
        // unread here, so the stream stays broken until it has been consumed.
        self.broken = true;
        ensure!(answer == (kind, size), "Git cat-file answered out of order");
        let mut bytes = vec![0; size];
        self.output
            .read_exact(&mut bytes)
            .context("Git cat-file ended early")?;
        let mut end = [0u8; 1];
        self.output
            .read_exact(&mut end)
            .context("Git cat-file ended early")?;
        ensure!(end == *b"\n", "Git cat-file answered out of order");
        self.broken = false;
        Ok(bytes)
    }

    /// Send one command and parse its header. An absent object refuses as a failed one-shot
    /// read of it does, naming the id and the fetch that supplies it.
    fn ask(&mut self, command: &str, oid: &str) -> Result<(String, usize)> {
        self.broken = true;
        let input = self.input.as_mut().context("Git cat-file input closed")?;
        input
            .write_all(format!("{command} {oid}\n").as_bytes())
            .and_then(|()| input.flush())
            .context("Git cat-file failed")?;
        let mut line = Vec::new();
        self.output
            .read_until(b'\n', &mut line)
            .context("Git cat-file failed")?;
        let line = line
            .strip_suffix(b"\n")
            .context("Git cat-file ended early")?;
        let line = std::str::from_utf8(line).context("Git cat-file answered out of order")?;
        let fields: Vec<&str> = line.split(' ').collect();
        match fields.as_slice() {
            [answered, "missing"] if *answered == oid => {
                self.broken = false;
                bail!(
                    "Git cat-file failed: object {oid} is not in the local object store; \
                     run `git fetch origin` and retry"
                )
            }
            [answered, kind, size] if *answered == oid => {
                let size = size.parse().context("Git cat-file answered out of order")?;
                self.broken = false;
                Ok(((*kind).to_owned(), size))
            }
            _ => bail!("Git cat-file answered out of order"),
        }
    }
}

impl Drop for Objects {
    fn drop(&mut self) {
        // Closing the input ends the batch; a stream left mid-object is killed instead.
        drop(self.input.take());
        if self.broken {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

#[derive(Clone)]
pub struct Git {
    pub root: PathBuf,
    /// The most bytes one scan batch of this store's units holds.
    pub(crate) batch: usize,
}

const EMPTY_TREE: &str = "4b825dc642cb6eb9a060e54bf8d69288fbee4904";

/// The tree `git merge-tree --write-tree` wrote for two commits. A conflicted merge still has a
/// tree, carrying conflict markers; `clean` says whether it has none.
pub struct LocalMerge {
    pub tree: String,
    pub clean: bool,
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
            batch: BATCH_LIMIT,
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

    /// `new`, with scan batches of at most `limit` bytes instead of `BATCH_LIMIT`, so a test
    /// can cut a small candidate into several batches. It only lowers the limit, and no
    /// command-line flag or environment variable reaches it.
    pub fn with_batch_limit(root: &Path, limit: usize) -> Result<Self> {
        ensure!(
            limit > 0 && limit <= BATCH_LIMIT,
            "a batch limit must be positive and at most the default"
        );
        Ok(Self {
            batch: limit,
            ..Self::new(root)?
        })
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
        if !output.status.success() {
            return Err(self.refusal(args, output.status));
        }
        ensure!(
            output.stdout.len() <= MAX_OUTPUT,
            "Git object output exceeds limit"
        );
        Ok(output.stdout)
    }

    /// Classify a failed Git operation without echoing its stderr or arguments: both can carry
    /// candidate bytes (ref names, paths, object content) that must not reach a diagnostic. The
    /// subcommand is ours, and an object id is a digest, so those two are named; an object the
    /// local store lacks is probed for directly and gets the remedy that supplies it.
    fn refusal(&self, args: &[&str], status: std::process::ExitStatus) -> anyhow::Error {
        let operation = args.first().copied().unwrap_or("command");
        let operation = if operation
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'-')
        {
            operation
        } else {
            "command"
        };
        let missing = args
            .iter()
            .flat_map(|arg| arg.split(|c: char| !c.is_ascii_hexdigit()))
            .filter(|oid| is_oid(oid))
            .find(|oid| {
                !self
                    .command()
                    .args(["cat-file", "-e", &format!("{oid}^{{object}}")])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .is_ok_and(|probe| probe.success())
            });
        let exit = status
            .code()
            .map_or_else(|| "a signal".to_owned(), |code| format!("exit {code}"));
        match missing {
            Some(oid) => anyhow::anyhow!(
                "Git {operation} failed ({exit}): object {oid} is not in the local object store; \
                 run `git fetch origin` and retry"
            ),
            None => anyhow::anyhow!("Git {operation} failed ({exit})"),
        }
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
        Objects::open(self)?.blob(oid, MAX_BLOB)
    }

    /// Git's own merge of two commits, computed in memory: no checkout, no index, and no
    /// attributes from the worktree, so a checked-out `.gitattributes` cannot pick a merge driver.
    pub fn merge_tree(&self, first: &str, second: &str) -> Result<LocalMerge> {
        ensure!(is_oid(first) && is_oid(second), "invalid merge input");
        self.ensure_no_merge_steering()?;
        let args = ["merge-tree", "--write-tree", "--no-messages", first, second];
        // Repository config can also change what a clean merge means (directory renames,
        // renormalization, rename detection); pin each to Git's default.
        let output = self
            .command()
            .args([
                "-c",
                "merge.directoryRenames=conflict",
                "-c",
                "merge.renormalize=false",
                "-c",
                "merge.renames=true",
                "-c",
                "diff.renames=true",
            ])
            .arg(format!("--attr-source={EMPTY_TREE}"))
            .args(args)
            .stderr(Stdio::null())
            .output()
            .context("Git plumbing failed")?;
        let clean = match output.status.code() {
            Some(0) => true,
            Some(1) => false,
            _ => return Err(self.refusal(&args, output.status)),
        };
        ensure!(
            output.stdout.len() <= MAX_OUTPUT,
            "Git object output exceeds limit"
        );
        let tree = output
            .stdout
            .split(|b| *b == b'\n')
            .next()
            .and_then(|line| std::str::from_utf8(line).ok())
            .filter(|tree| is_oid(tree))
            .context("Git merge-tree answered without a tree")?
            .to_owned();
        Ok(LocalMerge { tree, clean })
    }

    /// `--attr-source` and `core.attributesFile` do not cover `$GIT_DIR/info/attributes`, which
    /// Git always reads, nor a merge driver named by configuration: `merge.default` applies to
    /// every path without a `merge` attribute, and a `merge.<name>.driver` can shadow a built-in
    /// driver of the same name. Either could resolve a conflict and report the merge clean.
    fn ensure_no_merge_steering(&self) -> Result<()> {
        let held = self.text(&["rev-parse", "--git-path", "info/attributes"])?;
        let path = self.root.join(held);
        ensure!(
            !path.exists() || std::fs::read(path)?.is_empty(),
            "repository info/attributes refused for a local merge"
        );
        let args = ["config", "-z", "--name-only", "--get-regexp", r"^merge\."];
        let output = self
            .command()
            .args(args)
            .stderr(Stdio::null())
            .output()
            .context("Git plumbing failed")?;
        let names = match output.status.code() {
            Some(0) => output.stdout,
            Some(1) => Vec::new(),
            _ => return Err(self.refusal(&args, output.status)),
        };
        let steered = names
            .split(|b| *b == 0)
            .filter(|name| !name.is_empty())
            .any(|name| {
                let name = name.to_ascii_lowercase();
                name == b"merge.default" || name.ends_with(b".driver")
            });
        ensure!(
            !steered,
            "configured merge driver refused for a local merge"
        );
        Ok(())
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

    /// The units of every path whose entry differs from `old`. Each blob is read once here,
    /// for its digest, and again when its batch is scanned; none is held in between.
    fn units(
        objects: &mut Objects,
        tree: &BTreeMap<String, (String, String)>,
        old: &BTreeMap<String, (String, String)>,
    ) -> Result<Vec<UnitRef>> {
        let mut units = Vec::new();
        for (path, (mode, oid)) in tree {
            if old.get(path) == Some(&(mode.clone(), oid.clone())) {
                continue;
            }
            let previous = old.get(path);
            units.push(UnitRef::from(Unit {
                location: format!("filename:{path}"),
                bytes: path.as_bytes().to_vec(),
                workflow: false,
                inherited: previous.map(|_| path.as_bytes().to_vec()),
            }));
            let bytes = objects.blob(oid, MAX_BLOB)?;
            // An oversized predecessor cannot be read, so nothing is inherited from
            // it and the whole file is answerable. That fails closed.
            let predecessor = match previous {
                Some((_, old)) => objects.predecessor(old)?.map(|size| (old.clone(), size)),
                None => None,
            };
            units.push(UnitRef::object(
                format!("file:{path}"),
                path.starts_with(".github/workflows/")
                    && (path.ends_with(".yml") || path.ends_with(".yaml")),
                &bytes,
                (oid, "blob"),
                predecessor,
            ));
        }
        Ok(units)
    }

    pub fn candidate(
        &self,
        policy: &Policy,
        repository: &str,
        head: &str,
        tag_refs: &[String],
    ) -> Result<Candidate> {
        self.build(policy, repository, head, tag_refs, None)
    }

    /// The candidate for `head` with no tags, taking the units of every commit `known`
    /// already holds from it instead of reading them again. A commit's units depend only on
    /// its own objects and its first parent's tree, so they are the units a fresh build
    /// reads; every other commit is read and admitted exactly as `candidate` does.
    pub(crate) fn candidate_from(
        &self,
        policy: &Policy,
        repository: &str,
        head: &str,
        known: &Candidate,
    ) -> Result<Candidate> {
        self.build(policy, repository, head, &[], Some(known))
    }

    fn build(
        &self,
        policy: &Policy,
        repository: &str,
        head: &str,
        tag_refs: &[String],
        known: Option<&Candidate>,
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
        let mut spans = Vec::with_capacity(commits.len());
        let mut objects = Objects::open(self)?;
        let held: BTreeMap<&str, &[UnitRef]> = known
            .into_iter()
            .flat_map(|k| {
                k.binding
                    .commits
                    .iter()
                    .zip(&k.spans)
                    .map(|(commit, span)| (commit.as_str(), &k.units.entries[span.clone()]))
            })
            .collect();
        for commit in &commits {
            ensure!(is_oid(commit), "invalid commit coordinate");
            let start = units.len();
            if let Some(known) = held.get(commit.as_str()) {
                units.extend_from_slice(known);
                spans.push(start..units.len());
                continue;
            }
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
            units.extend(Self::units(&mut objects, &self.tree(commit)?, &old)?);
            units.push(UnitRef::object(
                format!("commit:{commit}"),
                false,
                &raw,
                (commit, "commit"),
                None,
            ));
            spans.push(start..units.len());
        }
        drop(objects);
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
            units.push(UnitRef::from(Unit {
                location: "tag-ref".into(),
                bytes: tag.as_bytes().to_vec(),
                workflow: false,
                inherited: None,
            }));
            while self.text(&["cat-file", "-t", &oid])? == "tag" {
                ensure!(tags.insert(oid.clone()), "duplicate or cyclic tag");
                let raw = self.read(&["cat-file", "tag", &oid])?;
                let next = raw
                    .split(|v| *v == b'\n')
                    .next()
                    .and_then(|v| v.strip_prefix(b"object "))
                    .context("malformed annotated tag")?;
                let next = std::str::from_utf8(next)?.to_owned();
                units.push(UnitRef::object(
                    format!("tag:{oid}"),
                    false,
                    &raw,
                    (&oid, "tag"),
                    None,
                ));
                ensure!(is_oid(&next), "invalid nested tag");
                oid = next;
            }
        }
        // No total: the units are scanned in batches, so a candidate's size is no limit.
        let manifest: Vec<_> = units
            .iter()
            .map(|u| (&u.location, &u.digest, u.workflow))
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
            units: Units {
                git: self.clone(),
                entries: units,
            },
            spans,
        })
    }

    pub fn staged(&self) -> Result<Units> {
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
        Ok(Units {
            git: self.clone(),
            entries: Self::units(&mut Objects::open(self)?, &tree, &old)?,
        })
    }

    pub fn historical(&self, baseline: &str) -> Result<Units> {
        Ok(Units {
            git: self.clone(),
            entries: Self::units(
                &mut Objects::open(self)?,
                &self.tree(baseline)?,
                &BTreeMap::new(),
            )?,
        })
    }

    pub fn verify_bot(&self, commits: &[String]) -> Result<()> {
        for oid in commits {
            let raw = self.read(&["cat-file", "commit", oid])?;
            for field in [b"author ".as_slice(), b"committer ".as_slice()] {
                let value = unique_header(&raw, field)?;
                if !exact_identity(value, crate::BOT_NAME, crate::BOT_EMAIL) {
                    bail!("outgoing commit must have the exact bot author and committer");
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, Git) {
        let dir = tempfile::tempdir().unwrap();
        let init = Command::new("git")
            .current_dir(dir.path())
            .args(["-c", "init.templateDir=", "init", "-q"])
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .status()
            .unwrap();
        assert!(init.success());
        let git = Git::new(dir.path()).unwrap();
        (dir, git)
    }

    fn write(git: &Git, bytes: &[u8]) -> String {
        let path = git.root.join("object-input");
        std::fs::write(&path, bytes).unwrap();
        git.text(&["hash-object", "-w", "--", "object-input"])
            .unwrap()
    }

    /// A refusal for size, type or absence must leave the batch in place: the inherited
    /// predecessor read swallows those refusals and the candidate reads on.
    #[test]
    fn a_refused_object_leaves_the_batch_answering_exactly() {
        let (_dir, git) = store();
        let small = write(&git, b"small\n");
        let large = write(&git, &[b'x'; 64]);
        let tree = git.text(&["mktree"]).unwrap();
        let absent = "0123456789abcdef0123456789abcdef01234567";
        let mut objects = Objects::open(&git).unwrap();
        let refused = objects.blob(&large, 63).unwrap_err().to_string();
        assert!(refused.contains("exceeds scan limit"), "{refused}");
        assert_eq!(objects.blob(&small, 63).unwrap(), b"small\n");
        let refused = objects.blob(absent, 63).unwrap_err().to_string();
        assert!(
            refused.contains(absent)
                && refused.contains("local object store")
                && refused.contains("git fetch origin"),
            "{refused}"
        );
        assert_eq!(objects.blob(&large, 64).unwrap(), vec![b'x'; 64]);
        assert!(objects.blob(&tree, 1 << 20).is_err());
        assert_eq!(objects.blob(&small, 63).unwrap(), b"small\n");
        assert!(objects.blob("not an object id", 63).is_err());
        assert_eq!(objects.blob(&small, 6).unwrap(), b"small\n");
        assert!(objects.blob(&small, 5).is_err());
    }
}
