//! The argument check `b10x-gates bot` runs before any credential is minted.
//!
//! The bot runs `commit`, `tag`, `push` and `fetch` only. Everything else is refused
//! with the supported route in the text, so an agent does not have to find it alone.
//! `Github::git` runs this same check again, so the two cannot drift.
use anyhow::{Result, bail};

const SUPPORTED: &str = "bot Git command must be commit, tag, push or fetch";
const GUARD: &str = "bot delivery cannot bypass hooks or inject Git configuration";
const MERGE_ROUTE: &str = "run `git merge --no-ff --no-commit <branch>`, then \
    `b10x-gates bot -- commit -F -` (no pathspec: a merge commits the whole index)";
/// `git push` long options a deletion can be spelled with, including any unique
/// prefix Git's option parser accepts.
const DELETING_OPTIONS: [&str; 3] = ["delete", "prune", "mirror"];
/// `git push` options whose value is the following argument, not a positional.
const VALUED_OPTIONS: [&str; 5] = ["-o", "--push-option", "--repo", "--receive-pack", "--exec"];

/// Refuse a bot Git invocation that the bot does not run, naming the supported route.
pub fn check(args: &[String], repository: Option<&str>) -> Result<()> {
    let repository = repository.unwrap_or("<owner>/<repo>");
    let verb = args.first().map(String::as_str).unwrap_or("");
    match verb {
        "commit" | "tag" | "fetch" => {}
        "push" => push(&args[1..], repository)?,
        "merge" => bail!("{SUPPORTED}; to merge, {MERGE_ROUTE}"),
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

fn delete_route(repository: &str, branch: &str) -> String {
    format!(
        "run `b10x-gates api --method DELETE --path \
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
