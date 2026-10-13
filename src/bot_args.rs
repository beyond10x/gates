//! The argument check `b10x-gates bot` runs before any credential is minted.
//!
//! The bot runs `commit`, `tag`, `push`, `fetch`, `merge` and `revert` as Git, and
//! `delete-branch` through the REST API. Everything else is refused with the supported
//! route in the text, so an agent does not have to find it alone. `Github::git` runs
//! this same check again, so the two cannot drift.
use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};

const SUPPORTED: &str = "bot Git command must be commit, tag, push, fetch, merge or revert, \
                         or the API verb delete-branch";
const GUARD: &str = "bot delivery cannot bypass hooks or inject Git configuration";
const MERGE_ROUTE: &str =
    "run `b10x-gates bot -- merge <branch>`, which commits the merge as the bot";

/// How an admitted long option takes its value.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Arity {
    /// No value; `--<option>=<value>` is refused.
    Flag,
    /// A value, inline after `=` or as the next argument.
    Required,
    /// An optional value, inline after `=` only (`--gpg-sign[=<keyid>]`).
    Inline,
}

/// The long options `merge` admits, by exact name (`gates.delivery.Merge`). Every
/// other one is refused, so nothing unlisted can choose a strategy or a resolution,
/// skip the bot's own commit, resume or abandon an operation, bypass hooks, inject
/// configuration or name a second commit. An abbreviation Git would accept is refused
/// too: when unsure, refuse.
const MERGE_LONG: [(&str, Arity); 24] = [
    ("no-ff", Arity::Flag),
    ("quiet", Arity::Flag),
    ("verbose", Arity::Flag),
    ("stat", Arity::Flag),
    ("no-stat", Arity::Flag),
    ("summary", Arity::Flag),
    ("compact-summary", Arity::Flag),
    ("signoff", Arity::Flag),
    ("no-signoff", Arity::Flag),
    ("message", Arity::Required),
    ("file", Arity::Required),
    ("into-name", Arity::Required),
    ("cleanup", Arity::Required),
    ("no-edit", Arity::Flag),
    ("gpg-sign", Arity::Inline),
    ("no-gpg-sign", Arity::Flag),
    ("verify-signatures", Arity::Flag),
    ("no-verify-signatures", Arity::Flag),
    ("progress", Arity::Flag),
    ("no-progress", Arity::Flag),
    ("rerere-autoupdate", Arity::Flag),
    ("no-rerere-autoupdate", Arity::Flag),
    ("overwrite-ignore", Arity::Flag),
    ("no-overwrite-ignore", Arity::Flag),
];
/// The long options `revert` admits, by exact name (`gates.delivery.Revert`). `git
/// revert` hands every option it does not know to its revision walker, where
/// `--do-walk`, `--all`, `--tags`, `--stdin` or `--not` would revert more than the
/// one revision; Git never abbreviates those, so only exact names are admitted.
const REVERT_LONG: [(&str, Arity); 9] = [
    ("mainline", Arity::Required),
    ("cleanup", Arity::Required),
    ("no-edit", Arity::Flag),
    ("signoff", Arity::Flag),
    ("gpg-sign", Arity::Inline),
    ("no-gpg-sign", Arity::Flag),
    ("rerere-autoupdate", Arity::Flag),
    ("no-rerere-autoupdate", Arity::Flag),
    ("reference", Arity::Flag),
];
/// Short letters refused by name for both verbs, ahead of the admitted ones: `-s` is
/// `--strategy` to `merge` and `--signoff` to `revert`, `-n` is `--no-stat` to `merge`
/// and `--no-commit` to `revert`, `-X`, `-e` and `-c` choose a resolution, an editor
/// or configuration.
const FORBIDDEN_SHORT: &str = "sXnec";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Merge,
    Revert,
}

impl Verb {
    pub fn name(self) -> &'static str {
        match self {
            Verb::Merge => "merge",
            Verb::Revert => "revert",
        }
    }
}

/// A `merge` or `revert` the bot runs: Git's no-commit run, then the bot's commit.
#[derive(Debug)]
pub struct Integration {
    pub verb: Verb,
    /// The caller's options Git's no-commit run receives; the bot's own options follow
    /// them, so Git's last-wins parsing cannot undo `--no-commit`.
    pub options: Vec<String>,
    /// The commit message options (`-m <msg>` or `-F <file>`) for the bot's commit of
    /// a merge; empty keeps Git's prepared message.
    pub message: Vec<String>,
    pub revision: String,
    /// The revision followed a `--`.
    pub separated: bool,
}

/// Sort a `merge` or `revert` into the options Git runs with and the message the bot
/// commits with, refusing what `gates.delivery.Merge` and `Revert` refuse.
pub fn integration(args: &[String]) -> Result<Integration> {
    let verb = match args.first().map(String::as_str) {
        Some("merge") => Verb::Merge,
        Some("revert") => Verb::Revert,
        _ => bail!("{SUPPORTED}"),
    };
    let name = verb.name();
    let admitted_long: &[(&str, Arity)] = match verb {
        Verb::Merge => &MERGE_LONG,
        Verb::Revert => &REVERT_LONG,
    };
    // Admitted short letters: those taking a value, then flags.
    let (valued_short, flag_short) = match verb {
        Verb::Merge => ("mF", "qv"),
        Verb::Revert => ("m", ""),
    };
    let admitted = || {
        admitted_long
            .iter()
            .map(|(o, _)| format!("--{o}"))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut options = Vec::new();
    let mut message: Vec<String> = Vec::new();
    let mut revisions: Vec<String> = Vec::new();
    let mut rest = args[1..].iter();
    let mut separated = false;
    while let Some(argument) = rest.next() {
        if separated || argument == "-" || !argument.starts_with('-') {
            revisions.push(argument.clone());
            continue;
        }
        if argument == "--" {
            separated = true;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let (option, inline) = match long.split_once('=') {
                Some((option, value)) => (option, Some(value)),
                None => (long, None),
            };
            let Some(&(_, arity)) = admitted_long.iter().find(|(o, _)| *o == option) else {
                bail!(
                    "bot {name} refuses `--{}`: it admits only {}, each by its full name",
                    option.escape_debug(),
                    admitted()
                );
            };
            let value = match (arity, inline) {
                (Arity::Flag, Some(_)) => {
                    bail!("bot {name} refuses `--{option}=`: `--{option}` takes no value")
                }
                (Arity::Required, Some(value)) => Some(value.to_string()),
                (Arity::Required, None) => Some(
                    rest.next()
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("bot {name} `--{option}` needs a value"))?,
                ),
                (Arity::Flag | Arity::Inline, _) => None,
            };
            match (verb, option, value) {
                (Verb::Merge, "message", Some(value)) => message.extend(["-m".into(), value]),
                (Verb::Merge, "file", Some(value)) => message.extend(["-F".into(), value]),
                (_, option, Some(value)) => {
                    options.extend([format!("--{option}"), value]);
                }
                _ => options.push(argument.clone()),
            }
            continue;
        }
        // A short cluster: flags, then at most one option whose value is the rest of
        // the cluster or, when nothing follows it, the next argument. A letter refused
        // by name is named ahead of one that is merely not admitted.
        let cluster = &argument[1..];
        let mut flags = String::new();
        let mut unadmitted = None;
        for (i, letter) in cluster.char_indices() {
            if FORBIDDEN_SHORT.contains(letter) {
                bail!("bot {name} refuses `-{letter}`");
            }
            let required = valued_short.contains(letter);
            if !required && letter != 'S' {
                if !flag_short.contains(letter) {
                    unadmitted.get_or_insert(letter);
                }
                flags.push(letter);
                continue;
            }
            let attached = &cluster[i + letter.len_utf8()..];
            if letter == 'S' {
                // `-S[<keyid>]`: an optional value, attached only.
                options.push(format!("-S{attached}"));
                break;
            }
            let value = if attached.is_empty() {
                rest.next()
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("bot {name} `-{letter}` needs a value"))?
            } else {
                attached.to_string()
            };
            match verb {
                Verb::Merge => message.extend([format!("-{letter}"), value]),
                Verb::Revert => options.extend(["-m".into(), value]),
            }
            break;
        }
        if let Some(letter) = unadmitted {
            bail!(
                "bot {name} refuses `-{}`: it admits only {}{}, each by its full name",
                letter.escape_debug(),
                [valued_short, "S", flag_short]
                    .concat()
                    .chars()
                    .map(|c| format!("-{c}, "))
                    .collect::<String>(),
                admitted()
            );
        }
        if !flags.is_empty() {
            options.push(format!("-{flags}"));
        }
    }
    let files = message.iter().step_by(2).filter(|o| *o == "-F").count();
    if files > 1 || (files == 1 && message.len() > 2) {
        bail!("bot {name} takes one `-F <file>` or `-m <message>` options, not both");
    }
    let [revision] = revisions.as_slice() else {
        bail!(
            "bot {name} takes exactly one revision, {} given: no octopus merge and no range",
            revisions.len()
        );
    };
    if revision.contains("..")
        || revision.starts_with('^')
        || ["^@", "^!", "^-"].iter().any(|r| revision.contains(r))
    {
        bail!("bot {name} takes exactly one revision, not the range `{revision}`");
    }
    Ok(Integration {
        verb,
        options,
        message,
        revision: revision.clone(),
        separated,
    })
}
/// `git push` long options a deletion can be spelled with, including any unique
/// prefix Git's option parser accepts.
const DELETING_OPTIONS: [&str; 3] = ["delete", "prune", "mirror"];
/// `git push` options whose value is the following argument, not a positional.
const VALUED_OPTIONS: [&str; 5] = ["-o", "--push-option", "--repo", "--receive-pack", "--exec"];

/// Refuse a bot Git invocation that the bot does not run, naming the supported route.
pub fn check(args: &[String], repository: Option<&str>) -> Result<()> {
    let given = repository;
    let repository = repository.unwrap_or("<owner>/<repo>");
    let verb = args.first().map(String::as_str).unwrap_or("");
    match verb {
        "commit" | "tag" | "fetch" => {}
        "delete-branch" => {
            // Its own complete check: one branch, no option, a named repository.
            delete_branch(args, given)?;
            return Ok(());
        }
        "push" => push(&args[1..], repository)?,
        "merge" | "revert" => {
            integration(args)?;
        }
        "pull" => {
            bail!("{SUPPORTED}; to pull, run `b10x-gates bot -- fetch origin`, then {MERGE_ROUTE}")
        }
        "rebase" | "cherry-pick" | "am" => bail!(
            "{SUPPORTED}; `{verb}` rewrites or re-creates commits the pre-push check then \
             refuses; instead {MERGE_ROUTE}"
        ),
        _ => bail!(
            "{SUPPORTED}; to merge, {MERGE_ROUTE}; to delete a branch, {}",
            delete_route(repository, "<branch>")
        ),
    }
    // Every argument is read, including those after `--`: when unsure, refuse.
    if args[1..].iter().any(|a| guarded(verb, a)) {
        bail!("{GUARD}");
    }
    Ok(())
}

/// Long options that run a caller-chosen command or inject configuration. Git takes
/// any unique prefix of a long option, so every non-empty prefix is refused:
/// `git push --e=<command>` is `--exec`.
const EXECUTING_OPTIONS: [&str; 4] = ["receive-pack", "upload-pack", "exec", "config-env"];
/// Short options whose value is the rest of the cluster, per verb: an `n` after one
/// of them is part of a value, an `n` before it is `--no-verify`.
fn short_valued(verb: &str) -> Option<&'static str> {
    match verb {
        "commit" => Some("mFCct"),
        "push" => Some("o"),
        _ => None,
    }
}

/// One argument that would bypass hooks or inject Git configuration.
fn guarded(verb: &str, argument: &str) -> bool {
    if argument == "-n" || argument == "-c" {
        return true;
    }
    if let Some(long) = argument.strip_prefix("--") {
        let name = long.split('=').next().unwrap_or("");
        return name.starts_with("config-env")
            || name.starts_with("exec")
            || (name.len() >= "no-v".len() && "no-verify".starts_with(name))
            || (!name.is_empty() && EXECUTING_OPTIONS.iter().any(|o| o.starts_with(name)));
    }
    let (Some(cluster), Some(valued)) = (argument.strip_prefix('-'), short_valued(verb)) else {
        return false;
    };
    cluster
        .chars()
        .take_while(|c| !valued.contains(*c))
        .any(|c| c == 'n')
}

/// The guarded verb for a merged branch, then the raw API route, which stays the only
/// way to delete an unmerged one.
fn delete_route(repository: &str, branch: &str) -> String {
    format!(
        "run `b10x-gates bot --repository {repository} -- delete-branch {branch}`, which \
         deletes it only when its tip is merged into the default branch; for an unmerged \
         branch, run `b10x-gates api --method DELETE --path \
         /repos/{repository}/git/refs/heads/{branch} --output <file>`, admitted only where \
         the policy admits that API write"
    )
}

fn branch_name(reference: &str) -> &str {
    reference.strip_prefix("refs/heads/").unwrap_or(reference)
}

/// Refuse every deletion form of `push`. Arguments after `--` are inspected the same
/// way: when unsure, refuse.
fn push(args: &[String], repository: &str) -> Result<()> {
    let mut deleting_option = false;
    let mut positionals: Vec<&str> = Vec::new();
    let mut refspec_branches: Vec<&str> = Vec::new();
    let mut skip_value = false;
    for argument in args {
        let argument = argument.as_str();
        if skip_value {
            skip_value = false;
            continue;
        }
        if let Some(long) = argument.strip_prefix("--") {
            let name = long.split('=').next().unwrap_or("");
            if !name.is_empty() && DELETING_OPTIONS.iter().any(|o| o.starts_with(name)) {
                deleting_option = true;
            }
            skip_value = VALUED_OPTIONS.contains(&argument);
            continue;
        }
        if let Some(short) = argument.strip_prefix('-')
            && !short.is_empty()
        {
            // A cluster such as `-fd` carries `-d`; `-o` takes the rest of the cluster,
            // or the next argument when nothing follows it, as its value.
            let (flags, value) = short.split_once('o').unwrap_or((short, "-"));
            if flags.contains('d') {
                deleting_option = true;
            }
            skip_value = value.is_empty();
            continue;
        }
        let refspec = argument.trim_start_matches('+');
        if let Some(destination) = refspec.strip_prefix(':') {
            refspec_branches.push(branch_name(destination));
        }
        positionals.push(argument);
    }
    if !deleting_option && refspec_branches.is_empty() {
        return Ok(());
    }
    let mut branches = refspec_branches;
    if deleting_option {
        branches.extend(positionals.iter().skip(1).map(|b| branch_name(b)));
    }
    branches.retain(|b| !b.is_empty() && !b.contains(':') && !b.starts_with('+'));
    branches.dedup();
    if branches.is_empty() {
        branches.push("<branch>");
    }
    let routes: Vec<String> = branches
        .iter()
        .map(|b| delete_route(repository, b))
        .collect();
    bail!(
        "bot push cannot delete a remote branch; {}",
        routes.join("; ")
    )
}

/// A `delete-branch` the argument check admitted: a well-formed `<owner>/<repo>` and
/// a branch name that addresses `refs/heads/<branch>` and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchDeletion {
    pub repository: String,
    /// The branch name without `refs/heads/`.
    pub branch: String,
}

/// The argument shape and name refusals of `gates.delivery.DeleteBranch`, all before
/// any credential is minted: a repository resolved (`delete_branch_repository`) and
/// well-formed, no option, exactly one branch, and a name that is a branch and nothing
/// else.
pub fn delete_branch(args: &[String], repository: Option<&str>) -> Result<BranchDeletion> {
    if args.first().map(String::as_str) != Some("delete-branch") {
        bail!("{SUPPORTED}");
    }
    let Some(repository) = repository else {
        bail!(
            "bot delete-branch needs a repository: pass --repository <owner>/<repo> \
             (`b10x-gates bot --repository <owner>/<repo> -- delete-branch <branch>`), or \
             run `b10x-gates install` in the repository so its hooks' configuration names it"
        );
    };
    if !repository_shaped(repository) {
        bail!(
            "bot delete-branch needs --repository <owner>/<repo>, not `{}`",
            repository.escape_debug()
        );
    }
    let rest = &args[1..];
    if rest.len() != 1 || rest.iter().any(|a| a.starts_with('-')) {
        bail!(
            "bot delete-branch takes exactly one branch and no option, {} argument(s) given: \
             run `b10x-gates bot --repository {repository} -- delete-branch <branch>`",
            rest.len()
        );
    }
    let branch = branch_to_delete(&rest[0])?;
    Ok(BranchDeletion {
        repository: repository.to_string(),
        branch,
    })
}

/// The repository `delete-branch` deletes in, resolved before any credential is
/// minted: `--repository` when given, else the `repository` of the installed hooks'
/// protected configuration (`<git common dir>/b10x-gates-hooks/config.json`), as the
/// hooks read it for `commit` and `push`. `None` when neither exists, which
/// `delete_branch` refuses naming both routes. A configuration that is present but
/// untrusted, unparsable or not `<owner>/<repo>` is refused with its cause.
pub fn delete_branch_repository(root: &Path, flag: Option<&str>) -> Result<Option<String>> {
    if let Some(flag) = flag {
        return Ok(Some(flag.to_string()));
    }
    Ok(installed_configuration(
        root,
        "bot delete-branch",
        "pass --repository <owner>/<repo> or run `b10x-gates install` in the repository",
    )?
    .map(|installed| installed.repository))
}

/// The installed hooks' protected configuration (`<git common dir>/b10x-gates-hooks/
/// config.json`), read as the hooks read it. `None` when the directory is no
/// repository or no configuration is installed. A configuration that is present but
/// untrusted, unparsable or whose repository is not `<owner>/<repo>` is refused with
/// its cause; every refusal is prefixed with `verb` and ends with `remedy`.
pub fn installed_configuration(
    root: &Path,
    verb: &str,
    remedy: &str,
) -> Result<Option<crate::hooks::Config>> {
    let Some(common) = common_directory(root, verb, remedy)? else {
        return Ok(None);
    };
    let config = common.join(crate::hooks::DIRECTORY).join("config.json");
    match std::fs::symlink_metadata(&config) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        _ => {}
    }
    let installed: crate::hooks::Config =
        serde_json::from_slice(&crate::policy::protected_read(&config)?).map_err(|_| {
            anyhow::anyhow!(
                "{verb}: installed hook configuration {} is invalid; {remedy}",
                config.display()
            )
        })?;
    if !repository_shaped(&installed.repository) {
        bail!(
            "{verb}: installed hook configuration {} names the repository `{}`, \
             not <owner>/<repo>; {remedy}",
            config.display(),
            installed.repository.escape_debug()
        );
    }
    Ok(Some(installed))
}

/// The Git common directory of `root`, located the way `hooks::directory` locates it but
/// without `Git::new`'s history guards: a shallow or grafted repository still has its
/// hooks installed, and reading where they live proves no history. `None` only when Git
/// says `root` is not a repository; any other failure is refused with its exit status
/// (Git's own stderr may carry path bytes and is not echoed).
fn common_directory(root: &Path, verb: &str, remedy: &str) -> Result<Option<PathBuf>> {
    let git = crate::git::Git {
        root: root.to_path_buf(),
    };
    let output = git
        .command()
        .env("LC_ALL", "C")
        .args(["rev-parse", "--path-format=absolute", "--git-common-dir"])
        .output()
        .with_context(|| format!("{verb}: Git could not start to locate the repository"))?;
    if !output.status.success() {
        if output.stderr.starts_with(b"fatal: not a git repository") {
            return Ok(None);
        }
        bail!(
            "{verb}: Git could not locate the repository at {} ({}), so its \
             installed hook configuration cannot be read; {remedy}",
            root.display(),
            output
                .status
                .code()
                .map_or_else(|| "a signal".to_owned(), |code| format!("exit {code}"))
        );
    }
    let common = String::from_utf8(output.stdout)
        .with_context(|| format!("{verb}: the Git common directory is not UTF-8"))?;
    Ok(Some(PathBuf::from(common.trim_end_matches('\n'))))
}

/// `<owner>/<repo>`: two non-empty segments of ASCII letters, digits, `-`, `_` and `.`,
/// neither a dot segment, so the repository can never change the request path.
fn repository_shaped(repository: &str) -> bool {
    let mut segments = repository.split('/');
    let (Some(owner), Some(name), None) = (segments.next(), segments.next(), segments.next())
    else {
        return false;
    };
    [owner, name].iter().all(|s| {
        !s.is_empty()
            && !s.starts_with('.')
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    })
}

/// The branch a name addresses, or the cause it is refused. Only `refs/heads/` is
/// addressed, so a tag is never deleted; the rest follows `git check-ref-format`.
fn branch_to_delete(name: &str) -> Result<String> {
    let refuse = |cause: &str| -> Result<String> {
        bail!(
            "bot delete-branch refuses the branch name `{}`: {cause}",
            name.escape_debug()
        )
    };
    let branch = match name.strip_prefix("refs/") {
        Some(rest) => match rest.strip_prefix("heads/") {
            Some(branch) => branch,
            None if rest.starts_with("tags/") => {
                return refuse("it names a tag, and the bot never deletes a tag");
            }
            None => return refuse("only `refs/heads/` is addressed"),
        },
        None => name,
    };
    if branch.is_empty() {
        return refuse("it is empty");
    }
    if let Some(c) = branch
        .chars()
        .find(|c| c.is_control() || c.is_whitespace() || ":~^?*[\\".contains(*c))
    {
        return refuse(&format!("it contains `{}`", c.escape_debug()));
    }
    for sequence in ["..", "@{"] {
        if branch.contains(sequence) {
            return refuse(&format!("it contains `{sequence}`"));
        }
    }
    if branch == "@" {
        return refuse("`@` is not a branch");
    }
    for ending in [".lock", "/", "."] {
        if branch.ends_with(ending) {
            return refuse(&format!("it ends with `{ending}`"));
        }
    }
    for segment in branch.split('/') {
        if segment.is_empty() {
            return refuse("it has an empty component");
        }
        if segment.starts_with('.') || segment.ends_with(".lock") {
            return refuse("a component starts with `.` or ends with `.lock`");
        }
    }
    Ok(branch.to_string())
}
