//! Coordinated hooks preserve existing worktree hooks and replace only an explicitly identified guard.
use crate::{
    digest, evidence,
    git::{Git, Unit},
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
}

pub fn install(root: &Path, mut config: Config, retire: Option<&str>) -> Result<()> {
    let git = Git::new(root)?;
    Policy::load(&config.policy)?.repository(&config.repository)?;
    config.policy = fs::canonicalize(&config.policy)?;
    config.key = fs::canonicalize(&config.key)?;
    config.scanner = fs::canonicalize(&config.scanner)?;
    let common =
        PathBuf::from(git.text(&["rev-parse", "--path-format=absolute", "--git-common-dir"])?);
    let installed = common.join("b10x-gates-hooks");
    let mut originals = vec![common.join("hooks")];
    if let Ok(current) = git.text(&["config", "--get", "core.hooksPath"]) {
        let current = if Path::new(&current).is_absolute() {
            PathBuf::from(current)
        } else {
            fs::canonicalize(root)?.join(current)
        };
        if current == installed {
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
    for original in originals {
        for hook in HOOKS {
            let path = original.join(hook);
            if !path.is_file() {
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
    for hook in HOOKS {
        let target = installed.join(hook);
        let staged = installed.join(format!(".{hook}.new"));
        fs::copy(std::env::current_exe()?, &staged)?;
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

pub fn invoked() -> Option<String> {
    let arg = std::env::args_os().next()?;
    let name = Path::new(&arg).file_name()?.to_str()?.to_owned();
    HOOKS.contains(&name.as_str()).then_some(name)
}

pub fn run(name: &str, args: &[String]) -> Result<()> {
    let exe = std::env::current_exe()?;
    let directory = exe.parent().context("hook directory unavailable")?;
    let config: Config =
        serde_json::from_slice(&policy::protected_read(&directory.join("config.json"))?)
            .map_err(|_| anyhow::anyhow!("hook configuration invalid"))?;
    let mut input = Vec::new();
    if matches!(name, "pre-push" | "post-rewrite" | "reference-transaction") {
        std::io::stdin().read_to_end(&mut input)?;
    }
    // Existing hooks can stage files or rewrite a message. Scan their final result.
    if let Some(previous) = config.previous.get(name) {
        for path in previous {
            let mut child = Command::new(path)
                .args(args)
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
        let mut units = Vec::new();
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
                });
            }
        } else if name == "commit-msg" {
            let path = args.first().context("commit message path missing")?;
            units.push(Unit {
                location: "commit-message".into(),
                bytes: fs::read(path)?,
                workflow: false,
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
                git.verify_bot(&candidate.binding.commits)?;
                let retained = directory.join(format!(
                    "{}.receipt.json",
                    digest(&serde_json::to_vec(&candidate.binding)?)
                ));
                let previous = fs::read(&retained)
                    .ok()
                    .and_then(|v| serde_json::from_slice::<evidence::Receipt>(&v).ok());
                if previous
                    .as_ref()
                    .is_none_or(|r| evidence::verify(&policy, &candidate, r).is_err())
                {
                    let key = evidence::read_key(&config.key)?;
                    let receipt = evidence::check(&policy, &candidate, &key, &mut scanner)?;
                    policy::private_write(&retained, &serde_json::to_vec(&receipt)?)?;
                }
                // Destination ref names are also untrusted data, including branch names.
                units.push(Unit {
                    location: "push-ref".into(),
                    bytes: fields[2].as_bytes().to_vec(),
                    workflow: false,
                });
            }
        }
        let report = scan::run(&policy, &config.repository, &units, &mut scanner)?;
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
