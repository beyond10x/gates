//! Coordinated hooks preserve existing worktree hooks and replace only an explicitly identified guard.
use crate::{
    digest, evidence,
    git::{Git, Unit, Units},
    policy::{self, Policy},
    scan::{self, Gitleaks},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

/// The one real copy of the binary in a repository's hook directory. Not a hook name,
/// so `invoked()` never dispatches on it.
const PINNED: &str = "b10x-gates";

const HOOKS: [&str; 13] = [
    "pre-commit",
    "commit-msg",
    "pre-push",
    "post-checkout",
    "post-commit",
    "post-merge",
    "pre-rebase",
    "prepare-commit-msg",
    "post-rewrite",
    "applypatch-msg",
    "pre-applypatch",
    "post-applypatch",
    "reference-transaction",
];

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub repository: String,
    pub policy: PathBuf,
    pub key: PathBuf,
    pub scanner: PathBuf,
    pub previous: BTreeMap<String, Vec<PathBuf>>,
    pub retired_pre_push_digest: Option<String>,
    /// The `b10x-gates` version that installed these hooks. The pinned inode does not
    /// change under `cargo install --force`, so a stale hook is otherwise silent.
    #[serde(default)]
    pub installed_version: String,
}

pub fn install(root: &Path, mut config: Config, retire: Option<&str>) -> Result<()> {
    let git = Git::new(root)?;
    policy::protect(&config.policy)?;
    Policy::load(&config.policy)?.repository(&config.repository)?;
    config.policy = fs::canonicalize(&config.policy)?;
    config.key = fs::canonicalize(&config.key)?;
    config.scanner = fs::canonicalize(&config.scanner)?;
    config.installed_version = crate::VERSION.into();
    let installed = directory(&git)?;
    let common = installed
        .parent()
        .context("Git common directory unavailable")?;
    // The hook directory by its real path: every comparison below uses it, so a symlink, a
    // `..` or a trailing separator cannot make the installed directory look like another one.
    let own = real_directory(&installed);
    let mut originals = vec![common.join("hooks")];
    if let Ok(current) = git.text(&["config", "--get", "core.hooksPath"]) {
        let current = if Path::new(&current).is_absolute() {
            PathBuf::from(current)
        } else {
            fs::canonicalize(root)?.join(current)
        };
        if current == installed || real_directory(&current) == own {
            let held: Config =
                serde_json::from_slice(&policy::protected_read(&installed.join("config.json"))?)?;
            ensure!(
                held.repository == config.repository,
                "installed hook repository mismatch"
            );
            config.previous = held.previous;
            config.retired_pre_push_digest = held.retired_pre_push_digest;
            originals.clear();
        } else {
            originals.push(current);
        }
    }
    // A configuration written before this check may already name the installed hooks as the
    // hooks to preserve; each of those starts itself. Drop them.
    config
        .previous
        .values_mut()
        .for_each(|paths| paths.retain(|path| !is_inside(path, &own)));
    config.previous.retain(|_, paths| !paths.is_empty());
    for original in originals {
        if real_directory(&original) == own {
            continue;
        }
        for hook in HOOKS {
            let path = original.join(hook);
            if !path.is_file() {
                continue;
            }
            // A link that resolves into the installed directory is the installed hook.
            if is_inside(&path, &own) {
                continue;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if fs::metadata(&path)?.permissions().mode() & 0o111 == 0 {
                    continue;
                }
            }
            if hook == "pre-push"
                && retire.is_some_and(|id| fs::read(&path).is_ok_and(|b| digest(&b) == id))
            {
                config.retired_pre_push_digest = retire.map(str::to_owned);
                continue;
            }
            let paths = config.previous.entry(hook.into()).or_default();
            let path = fs::canonicalize(path)?;
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    ensure!(
        retire.is_none() || config.retired_pre_push_digest.as_deref() == retire,
        "requested old guard digest was not found; no hooks changed"
    );
    fs::create_dir_all(&installed)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&installed, fs::Permissions::from_mode(0o700))?;
    }
    policy::private_write(
        &installed.join("config.json"),
        &serde_json::to_vec(&config)?,
    )?;
    // One pinned copy per repository; the 13 hook names are hardlinks to it. The hook
    // dispatches on `argv[0]`, so a link behaves as a copy did, and the inode still
    // pins the exact binary against an upgrade under a commit in flight. 6.9 MB a
    // repository instead of 89 MB. All links live beside the copy, so never cross-device.
    let pinned = installed.join(PINNED);
    let staged = installed.join(".pinned.new");
    let _ = fs::remove_file(&staged);
    fs::copy(std::env::current_exe()?, &staged)?;
    fs::rename(&staged, &pinned)?;
    for hook in HOOKS {
        let target = installed.join(hook);
        let staged = installed.join(format!(".{hook}.new"));
        let _ = fs::remove_file(&staged);
        match fs::hard_link(&pinned, &staged) {
            Ok(()) => {}
            Err(_) => {
                fs::copy(&pinned, &staged).context("hook could not be linked or copied")?;
            }
        }
        fs::rename(staged, target)?;
    }
    git.read(&[
        "config",
        "--local",
        "core.hooksPath",
        installed.to_str().context("hook path invalid")?,
    ])?;
    Ok(())
}

/// The hooks' directory name under the Git common directory.
pub const DIRECTORY: &str = "b10x-gates-hooks";

/// The environment variable that counts how many preserved hooks started this hook, and the
/// depth at which a chain is refused. A chain of one or two preserved hooks is normal.
const CHAIN_DEPTH: &str = "B10X_GATES_HOOK_DEPTH";
const MAX_CHAIN_DEPTH: u32 = 4;

/// `path` by its real path when it exists. When it does not, its parent's real path and its own
/// name, so a directory that is about to be created still compares by where it will be.
fn real_directory(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => fs::canonicalize(parent)
            .map(|real| real.join(name))
            .unwrap_or_else(|_| path.to_path_buf()),
        _ => path.to_path_buf(),
    })
}

/// Whether `path`, after every link, lies inside the directory `own` (a real path).
fn is_inside(path: &Path, own: &Path) -> bool {
    real_directory(path).starts_with(own)
}

/// The installed hook directory, where the pre-push hook retains its receipts.
pub fn directory(git: &Git) -> Result<PathBuf> {
    let common =
        PathBuf::from(git.text(&["rev-parse", "--path-format=absolute", "--git-common-dir"])?);
    Ok(common.join(DIRECTORY))
}

pub fn invoked() -> Option<String> {
    let arg = std::env::args_os().next()?;
    let name = Path::new(&arg).file_name()?.to_str()?.to_owned();
    HOOKS.contains(&name.as_str()).then_some(name)
}

/// Pre-push uses the same ancestry proof as publication, before receipt reuse.
pub fn verify_pre_push(
    git: &Git,
    policy: &Policy,
    repository: &str,
    head: &str,
    api: &impl crate::published_merge::AuthenticatedRead,
) -> Result<()> {
    crate::published_merge::verify(git, policy, repository, head, api)
}

pub fn run(name: &str, args: &[String]) -> Result<()> {
    let exe = std::env::current_exe()?;
    let directory = exe.parent().context("hook directory unavailable")?;
    let config: Config =
        serde_json::from_slice(&policy::protected_read(&directory.join("config.json"))?)
            .map_err(|_| anyhow::anyhow!("hook configuration invalid"))?;
    let depth: u32 = std::env::var(CHAIN_DEPTH)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    ensure!(
        depth < MAX_CHAIN_DEPTH,
        "hook chain deeper than {MAX_CHAIN_DEPTH} preserved hooks: a preserved hook starts this \
         hook again"
    );
    let own = real_directory(directory);
    let mut input = Vec::new();
    if matches!(name, "pre-push" | "post-rewrite" | "reference-transaction") {
        std::io::stdin().read_to_end(&mut input)?;
    }
    // Existing hooks can stage files or rewrite a message. Scan their final result.
    if let Some(previous) = config.previous.get(name) {
        for path in previous {
            // An entry inside this directory is an installed hook, and starting it starts this
            // one again without end. A configuration that holds one is repaired by `install`.
            if is_inside(path, &own) {
                eprintln!(
                    "b10x-gates: preserved hook {} for {name} is the hook itself; skipped. Run \
                     `b10x-gates install` to repair the configuration",
                    path.display()
                );
                continue;
            }
            let mut child = Command::new(path)
                .args(args)
                .env(CHAIN_DEPTH, (depth + 1).to_string())
                .stdin(if input.is_empty() {
                    Stdio::null()
                } else {
                    Stdio::piped()
                })
                .spawn()
                .context("preserved hook could not start")?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(&input)?;
            }
            ensure!(child.wait()?.success(), "preserved hook refused operation");
        }
    }
    let git = Git::new(Path::new("."))?;
    let mut scanner = Gitleaks {
        binary: config.scanner.clone(),
    };
    if matches!(name, "pre-commit" | "commit-msg" | "pre-push") {
        let policy = Policy::load(&config.policy)?;
        let mut units = Units::new(&git);
        if name == "pre-commit" {
            units = git.staged()?;
            for ident in ["GIT_AUTHOR_IDENT", "GIT_COMMITTER_IDENT"] {
                let bytes = git.read(&["var", ident])?;
                ensure!(
                    crate::git::exact_identity(
                        bytes.trim_ascii(),
                        crate::BOT_NAME,
                        crate::BOT_EMAIL
                    ),
                    "local commits require the exact bot author and committer; use b10x-gates bot"
                );
                units.push(Unit {
                    location: ident.into(),
                    bytes,
                    workflow: false,
                    inherited: None,
                });
            }
        } else if name == "commit-msg" {
            let path = args.first().context("commit message path missing")?;
            units.push(Unit {
                location: "commit-message".into(),
                bytes: fs::read(path)?,
                workflow: false,
                inherited: None,
            });
        } else {
            ensure!(
                std::env::var("B10X_BOT_PUSH").as_deref() == Ok("1"),
                "push through b10x-gates bot or publish"
            );
            let url = args.get(1).context("push destination missing")?;
            let expected = [
                format!("https://github.com/{}", config.repository),
                format!("git@github.com:{}", config.repository),
                format!("ssh://git@github.com/{}", config.repository),
            ];
            ensure!(
                expected
                    .iter()
                    .any(|p| url == p || url == &format!("{p}.git")),
                "push destination differs from enrolled repository"
            );
            for line in std::str::from_utf8(&input)?.lines() {
                let fields: Vec<_> = line.split_whitespace().collect();
                ensure!(
                    fields.len() == 4
                        && crate::git::is_oid(fields[1])
                        && crate::git::is_oid(fields[3]),
                    "malformed push update"
                );
                if fields[1].bytes().all(|b| b == b'0') {
                    continue;
                }
                let head = git.resolve(&format!("{}^{{commit}}", fields[1]))?;
                let tags = if fields[2].starts_with("refs/tags/") {
                    vec![fields[0].to_owned()]
                } else {
                    Vec::new()
                };
                let candidate = git.candidate(&policy, &config.repository, &head, &tags)?;
                verify_pre_push(
                    &git,
                    &policy,
                    &config.repository,
                    &head,
                    &crate::delivery::PushEvidence,
                )?;
                let retained = directory.join(format!(
                    "{}.receipt.json",
                    digest(&serde_json::to_vec(&candidate.binding)?)
                ));
                // Every receipt this hook retained is evidence to reuse: one for this exact
                // head, or one for an ancestor that leaves only the newer commits to scan.
                let previous = evidence::retained_in(directory);
                if !previous
                    .iter()
                    .any(|r| evidence::verify(&policy, &candidate, r).is_ok())
                {
                    let key = evidence::read_key(&config.key)?;
                    let checked = evidence::check_reusing(
                        &policy,
                        &git,
                        &candidate,
                        &previous,
                        &key,
                        &mut scanner,
                    )?;
                    policy::private_write(&retained, &serde_json::to_vec(&checked.receipt)?)?;
                }
                // Destination ref names are also untrusted data, including branch names.
                units.push(Unit {
                    location: "push-ref".into(),
                    bytes: fields[2].as_bytes().to_vec(),
                    workflow: false,
                    inherited: None,
                });
            }
        }
        let report = scan::run_batches(&policy, &config.repository, &units, &mut scanner)?;
        if !report.findings.is_empty() {
            policy::private_write(
                &directory.join("last-findings.json"),
                &serde_json::to_vec(&report.findings)?,
            )?;
        }
        report.require_success()?;
    }
    Ok(())
}
