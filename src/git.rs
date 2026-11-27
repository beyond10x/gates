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
    /// A blob, commit or tag object; for a changed file, also the blob it replaced.
    Object {
        oid: String,
        kind: &'static str,
        predecessor: Option<Predecessor>,
    },
}

/// The blob a changed file replaced, bound by what the build read of it. Git does not rehash
/// a loose object it reads, so the id alone does not bind the bytes the batch reads later.
#[derive(Clone)]
struct Predecessor {
    oid: String,
    length: usize,
    /// The SHA-256 of the bytes the build read.
    digest: String,
}

impl UnitRef {
    /// A unit for the object `(oid, kind)`, whose bytes are `bytes`.
    fn object(
        location: String,
        workflow: bool,
        bytes: &[u8],
        (oid, kind): (&str, &'static str),
        predecessor: Option<Predecessor>,
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
                self.length + predecessor.as_ref().map_or(0, |p| p.length)
            }
        }
    }

    /// The unit with its bytes. An object and its predecessor are read through `objects`,
    /// opened on first use, and each must be exactly the bytes the build bound; any read
    /// that fails refuses.
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
                let bytes = objects.bound(oid, kind, self.length, &self.digest)?;
                let inherited = predecessor
                    .as_ref()
                    .map(|p| objects.bound(&p.oid, "blob", p.length, &p.digest))
                    .transpose()?;
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

    /// The predecessor `oid` when it can be inherited from: a blob within the per-blob
    /// limit, read once and bound by its length and digest, its bytes not kept. An absent,
    /// oversized or other object is inherited from by nothing, so the whole file is
    /// answerable, which fails closed; a broken stream refuses.
    fn predecessor(&mut self, oid: &str) -> Result<Option<Predecessor>> {
        match self.blob(oid, MAX_BLOB) {
            Ok(bytes) => Ok(Some(Predecessor {
                oid: oid.to_owned(),
                length: bytes.len(),
                digest: digest(&bytes),
            })),
            Err(error) if self.broken => Err(error),
            Err(_) => Ok(None),
        }
    }

    /// Read the object `(oid, kind)` again, refusing unless its bytes are the `length` bytes
    /// whose SHA-256 is `bound`, as the build read them. Every lazy read goes through here.
    fn bound(&mut self, oid: &str, kind: &str, length: usize, bound: &str) -> Result<Vec<u8>> {
        let bytes = self.object(oid, kind, length)?;
        ensure!(
            bytes.len() == length && digest(&bytes) == bound,
            "Git object {oid} differs from the candidate it was bound in"
        );
        Ok(bytes)
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

/// The entries of `tree` that differ from `old`, in path order, each with the entry it
/// replaced. `units` reads the blobs of exactly these, and `blobs` lists the same set for
/// `supply`, so what is fetched and what is read cannot drift apart.
fn changes<'a>(
    tree: &'a BTreeMap<String, (String, String)>,
    old: &'a BTreeMap<String, (String, String)>,
) -> impl Iterator<
    Item = (
        &'a String,
        &'a (String, String),
        Option<&'a (String, String)>,
    ),
> {
    tree.iter()
        .filter(move |(path, entry)| old.get(*path) != Some(*entry))
        .map(move |(path, entry)| (path, entry, old.get(path)))
}

/// Every blob `units` reads for `tree` against `old`: each changed file and the blob it
/// replaced.
fn blobs(
    tree: &BTreeMap<String, (String, String)>,
    old: &BTreeMap<String, (String, String)>,
) -> BTreeSet<String> {
    changes(tree, old)
        .flat_map(|(_, (_, oid), previous)| {
            std::iter::once(oid.clone()).chain(previous.map(|(_, old)| old.clone()))
        })
        .collect()
}

/// The first parent a raw commit object names, if it names one.
fn first_parent(raw: &[u8]) -> Result<Option<&str>> {
    Ok(raw
        .split(|v| *v == b'\n')
        .take_while(|v| !v.is_empty())
        .find_map(|line| line.strip_prefix(b"parent "))
        .map(std::str::from_utf8)
        .transpose()?)
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

    /// Git on this repository, answering from the objects themselves.
    ///
    /// Some files of the local store stand in for commit objects: Git takes a commit's parents
    /// from them and does not open the commit. `new` refuses two of them, grafts and shallow
    /// files. The others are switched off here, for every call:
    ///
    /// - replace refs (`--no-replace-objects`);
    /// - the commit-graph, as the single file `objects/info/commit-graph`, as a chain under
    ///   `objects/info/commit-graphs/`, and as either of them in a store that
    ///   `objects/info/alternates` names (`core.commitGraph=false`). Git reads parents from it
    ///   in `rev-list`, `merge-base` and `merge-tree`, and does not check the file's checksum
    ///   when it reads it. An entry that names another first parent takes a commit out of the
    ///   ancestry walk and turns "is an ancestor" into "no".
    ///
    /// The multi-pack-index is switched off too (`core.multiPackIndex=false`). It holds no
    /// history: it says where in which pack an object's bytes lie, and with two offsets swapped
    /// Git reads one commit as another. Each pack's own index answers the same question, so
    /// nothing is lost. This closes that one file and not the class: an object whose bytes are
    /// not its own, in a pack index or as a loose file, is not found by the walk.
    pub fn command(&self) -> Command {
        let mut cmd = Command::new("git");
        cmd.current_dir(&self.root)
            .arg("--no-replace-objects")
            .args([
                "-c",
                "core.commitGraph=false",
                "-c",
                "core.multiPackIndex=false",
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
        let exit = status
            .code()
            .map_or_else(|| "a signal".to_owned(), |code| format!("exit {code}"));
        match self.missing(args) {
            Some(oid) => anyhow::anyhow!(
                "Git {operation} failed ({exit}): object {oid} is not in the local object store; \
                 run `git fetch origin` and retry"
            ),
            None => anyhow::anyhow!("Git {operation} failed ({exit})"),
        }
    }

    /// The first object id among `args` that the local store lacks.
    fn missing<'a>(&self, args: &[&'a str]) -> Option<&'a str> {
        args.iter()
            .copied()
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
            })
    }

    /// Whether `ancestor` is `descendant` or one of its ancestors. Git answers "no" with exit 1
    /// and signals an error with any other non-zero status (`git help merge-base`); only the
    /// first is `false`, so an object Git cannot read is never taken for "not an ancestor".
    pub fn is_ancestor(&self, ancestor: &str, descendant: &str) -> Result<bool> {
        let args = ["merge-base", "--is-ancestor", ancestor, descendant];
        let status = self
            .command()
            .args(args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .context("Git plumbing failed")?;
        match status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => Err(self.refusal(&args, status)),
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
        // Repository config can also change what a clean merge means; pin each such key to
        // Git's default. A `-c` on the command line wins over every configuration file and over
        // configuration passed through the environment.
        //
        // - `merge.directoryRenames`, `merge.renormalize`: off, a file moves or is rewritten
        //   only where a side did it.
        // - `merge.renames`, and `diff.renames` which it falls back to: on. With rename
        //   detection off, two sides that rename one file to two names merge cleanly, as one
        //   deletion and two additions.
        // - `merge.renameLimit`: a file count above the limit skips the exhaustive part of
        //   rename detection, with the same effect, so `merge.renameLimit=1` makes that conflict
        //   clean. Unset it falls back to `diff.renameLimit`, and with neither set Git merges
        //   with 7000 (`git help config`, Git 2.56.0); set here, `diff.renameLimit` is not read.
        //
        // Not pinned, because no value changes a clean answer or a clean tree:
        // `merge.conflictStyle` changes only the markers inside a conflicted file, and a
        // conflicted merge refuses before its tree is compared. `diff.algorithm` is not read by a
        // merge (`git help merge`: "ort defaults to diff-algorithm=histogram, while regular diffs
        // currently default to the diff.algorithm config setting").
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
                "-c",
                "merge.renameLimit=7000",
            ])
            .arg(format!("--attr-source={EMPTY_TREE}"))
            .args(args)
            .stderr(Stdio::null())
            .output()
            .context("Git plumbing failed")?;
        let clean = match output.status.code() {
            Some(0) => true,
            Some(1) => false,
            _ => {
                let refusal = self.refusal(&args, output.status);
                // An input commit the store lacks has its own remedy in `refusal`. Otherwise one
                // cause is a partial clone: a content merge reads blobs the clone left out, and
                // nothing is fetched here. Git's own merge, run once by hand, fetches exactly
                // those. It is one message, Git's failure first: only the outermost message of
                // an error is printed, and a clone that is not partial must still read what
                // failed.
                return Err(if self.missing(&args).is_some() {
                    refusal
                } else {
                    anyhow::anyhow!(
                        "{refusal}; if this clone is a partial clone, run `git merge-tree \
                         --write-tree {first} {second}` once, which lets Git fetch the blobs the \
                         merge reads, and retry"
                    )
                });
            }
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

    /// The units of every path whose entry differs from `old`. Each blob, predecessors
    /// included, is read once here, for its digest, and again when its batch is scanned;
    /// none is held in between.
    fn units(
        objects: &mut Objects,
        tree: &BTreeMap<String, (String, String)>,
        old: &BTreeMap<String, (String, String)>,
    ) -> Result<Vec<UnitRef>> {
        let mut units = Vec::new();
        for (path, (_, oid), previous) in changes(tree, old) {
            units.push(UnitRef::from(Unit {
                location: format!("filename:{path}"),
                bytes: path.as_bytes().to_vec(),
                workflow: false,
                inherited: previous.map(|_| path.as_bytes().to_vec()),
            }));
            // An oversized predecessor cannot be read, so nothing is inherited from
            // it and the whole file is answerable. That fails closed. It is read before
            // the file's own bytes, so the build holds one blob at a time.
            let predecessor = match previous {
                Some((_, old)) => objects.predecessor(old)?,
                None => None,
            };
            let bytes = objects.blob(oid, MAX_BLOB)?;
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
        // A partial clone holds no blob it has not read yet. Every blob the loop below reads
        // is listed first, from the commits and trees alone, and fetched in one request, so
        // the build reads the candidate a full clone reads, in one try.
        let promisors = self.promisors()?;
        if !promisors.is_empty() {
            let mut wanted = BTreeSet::new();
            for commit in commits.iter().filter(|c| !held.contains_key(c.as_str())) {
                ensure!(is_oid(commit), "invalid commit coordinate");
                let raw = self.read(&["cat-file", "commit", commit])?;
                let old = match first_parent(&raw)? {
                    Some(p) => self.tree(p)?,
                    None => BTreeMap::new(),
                };
                wanted.append(&mut blobs(&self.tree(commit)?, &old));
            }
            self.supply(&promisors, wanted)?;
        }
        let mut objects = Objects::open(self)?;
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
            let old = match first_parent(&raw)? {
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
        self.supply(&self.promisors()?, blobs(&tree, &old))?;
        Ok(Units {
            git: self.clone(),
            entries: Self::units(&mut Objects::open(self)?, &tree, &old)?,
        })
    }

    pub fn historical(&self, baseline: &str) -> Result<Units> {
        let tree = self.tree(baseline)?;
        let none = BTreeMap::new();
        self.supply(&self.promisors()?, blobs(&tree, &none))?;
        Ok(Units {
            git: self.clone(),
            entries: Self::units(&mut Objects::open(self)?, &tree, &none)?,
        })
    }

    /// The promisor remotes of a partial clone, in the order Git asks them for an object it
    /// lacks: the one `extensions.partialClone` names, then each with `remote.<name>.promisor`
    /// true. Empty for a clone that is not partial.
    fn promisors(&self) -> Result<Vec<String>> {
        let mut remotes = Vec::new();
        let named = self
            .command()
            .args(["config", "--get", "extensions.partialclone"])
            .stderr(Stdio::null())
            .output()
            .context("Git plumbing failed")?;
        match named.status.code() {
            Some(0) => remotes.extend(
                String::from_utf8(named.stdout)
                    .context("promisor remote name is not UTF-8")?
                    .lines()
                    .map(str::to_owned),
            ),
            Some(1) => {}
            _ => bail!("Git config failed reading the partial clone's promisor remote"),
        }
        let args = [
            "config",
            "--null",
            "--type=bool",
            "--get-regexp",
            r"^remote\..+\.promisor$",
        ];
        let flagged = self
            .command()
            .args(args)
            .stderr(Stdio::null())
            .output()
            .context("Git plumbing failed")?;
        let listed = match flagged.status.code() {
            Some(0) => flagged.stdout,
            Some(1) => Vec::new(),
            _ => bail!("Git config failed reading the promisor remotes"),
        };
        // `remote.<name>.promisor\n<true|false>\0` per key.
        for record in listed.split(|b| *b == 0).filter(|r| !r.is_empty()) {
            let record =
                std::str::from_utf8(record).context("promisor remote name is not UTF-8")?;
            let (key, value) = record
                .split_once('\n')
                .context("Git config answered without a value")?;
            let name = key
                .strip_prefix("remote.")
                .and_then(|key| key.strip_suffix(".promisor"))
                .context("Git config answered another key")?;
            if value == "true" {
                remotes.push(name.to_owned());
            }
        }
        remotes.retain(|name| !name.is_empty());
        let mut seen = BTreeSet::new();
        remotes.retain(|name| seen.insert(name.clone()));
        Ok(remotes)
    }

    /// The objects of `wanted` the local store does not hold, asked without a lazy fetch.
    fn absent(&self, wanted: &BTreeSet<String>) -> Result<Vec<String>> {
        let mut child = self
            .command()
            .args(["cat-file", "--batch-check=%(objectname)"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("Git cat-file could not start")?;
        let mut input = child
            .stdin
            .take()
            .context("Git cat-file input unavailable")?;
        let output = std::thread::scope(|scope| {
            let writer = scope.spawn(move || -> std::io::Result<()> {
                for oid in wanted {
                    writeln!(input, "{oid}")?;
                }
                input.flush()
            });
            let output = child.wait_with_output();
            let written = writer.join();
            (output, written)
        });
        let (output, written) = output;
        let output = output.context("Git cat-file failed")?;
        ensure!(
            output.status.success() && matches!(written, Ok(Ok(()))),
            "Git cat-file failed"
        );
        let mut absent = Vec::new();
        let mut answers = output.stdout.split(|b| *b == b'\n');
        for oid in wanted {
            let answer = answers.next().context("Git cat-file ended early")?;
            if answer == format!("{oid} missing").as_bytes() {
                absent.push(oid.clone());
            } else {
                ensure!(
                    answer == oid.as_bytes(),
                    "Git cat-file answered out of order"
                );
            }
        }
        Ok(absent)
    }

    /// Fetch `oids` from the promisor remote `remote` in one request, as Git's own lazy fetch
    /// asks for them: no negotiation, no tags, no ref or `FETCH_HEAD` written, no submodule
    /// and no maintenance run, and no prompt for a credential. Nothing is checked out; the
    /// objects arrive as a pack Git has hashed. The name follows `--`, so it is never read as
    /// an option.
    fn fetch_objects(&self, remote: &str, oids: &[String]) -> Result<std::process::ExitStatus> {
        let mut child = self
            .command()
            .args([
                "-c",
                "fetch.negotiationAlgorithm=noop",
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                "--recurse-submodules=no",
                "--no-auto-maintenance",
                "--no-write-commit-graph",
                "--filter=blob:none",
                "--stdin",
                "--",
                remote,
            ])
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .context("Git fetch could not start")?;
        let mut input = child.stdin.take().context("Git fetch input unavailable")?;
        let written = oids
            .iter()
            .try_for_each(|oid| writeln!(input, "{oid}"))
            .and_then(|()| input.flush());
        drop(input);
        let status = child.wait().context("Git fetch failed")?;
        written.context("Git fetch input refused")?;
        Ok(status)
    }

    /// In a partial clone, fetch every object of `wanted` the local store lacks from its
    /// promisor remotes, one request a remote, before anything reads them. The reads themselves
    /// never fetch (`command`). An object still absent afterwards refuses, so nothing is read
    /// as a full clone would not read it. With no promisor remote nothing runs here, and an
    /// absent object refuses where it is read, as before.
    fn supply(&self, promisors: &[String], wanted: BTreeSet<String>) -> Result<()> {
        if promisors.is_empty() || wanted.is_empty() {
            return Ok(());
        }
        let mut absent = self.absent(&wanted)?;
        let mut failed = None;
        for remote in promisors {
            if absent.is_empty() {
                break;
            }
            let status = self.fetch_objects(remote, &absent)?;
            if !status.success() {
                failed = Some(status);
            }
            absent = self.absent(&absent.into_iter().collect())?;
        }
        let Some(first) = absent.first() else {
            return Ok(());
        };
        let fetched = failed.map_or_else(String::new, |status| {
            let exit = status
                .code()
                .map_or_else(|| "a signal".to_owned(), |code| format!("exit {code}"));
            format!(" (the fetch ended with {exit}; Git's message is above)")
        });
        let more = match absent.len() - 1 {
            0 => String::new(),
            n => format!(" and {n} more object(s) this check reads"),
        };
        bail!(
            "Git fetch from the promisor remote did not supply object {first}{more}{fetched}: it \
             is not in the local object store of this partial clone; make the remote reachable \
             and retry"
        )
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

    /// Git does not rehash a loose object it reads, so a predecessor's id does not bind its
    /// bytes. `units` binds every predecessor a candidate or the index inherits from, and a
    /// same-length swap before the batch reads it must refuse.
    #[test]
    fn a_predecessor_swapped_after_it_was_bound_refuses() {
        let (_dir, git) = store();
        let old = write(&git, b"old line\n");
        let new = write(&git, b"new line\nold line\n");
        let fake = write(&git, b"new line\n");
        let entry = |oid: &str| {
            BTreeMap::from([("notes.md".to_owned(), ("100644".to_owned(), oid.to_owned()))])
        };
        let mut objects = Objects::open(&git).unwrap();
        let units = Units {
            git: git.clone(),
            entries: Git::units(&mut objects, &entry(&new), &entry(&old)).unwrap(),
        };
        drop(objects);
        let read = units.read_all().unwrap();
        assert_eq!(read[1].inherited.as_deref(), Some(b"old line\n".as_slice()));
        let loose = |oid: &str| {
            git.root
                .join(".git/objects")
                .join(&oid[..2])
                .join(&oid[2..])
        };
        std::fs::remove_file(loose(&old)).unwrap();
        std::fs::copy(loose(&fake), loose(&old)).unwrap();
        let refused = units
            .read_all()
            .err()
            .expect("a predecessor swapped after it was bound must refuse")
            .to_string();
        assert!(
            refused.contains(&old) && refused.contains("differs from the candidate"),
            "{refused}"
        );
    }
}
