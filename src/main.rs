use anyhow::{Context, Result, ensure};
use b10x_gates::{
    delivery::{self, Github},
    evidence::{self, Receipt},
    git::Git,
    hooks,
    policy::{self, Policy},
    scan::{self, Gitleaks},
};
use clap::{Parser, Subcommand};
use std::{collections::BTreeMap, fs, path::PathBuf};

#[derive(Parser)]
#[command(
    version,
    about = "Common security checks, signed Git evidence, and bot delivery"
)]
struct Args {
    #[arg(long, global = true, default_value = ".")]
    repo: PathBuf,
    #[arg(long, global = true, env = "B10X_GATES_POLICY")]
    policy: Option<PathBuf>,
    #[arg(long, global = true, env = "B10X_GATES_KEY")]
    key: Option<PathBuf>,
    #[arg(long, global = true, env = "B10X_GATES_GITLEAKS")]
    gitleaks: Option<PathBuf>,
    #[arg(long, global = true)]
    repository: Option<String>,
    #[command(subcommand)]
    command: Action,
}

#[derive(Subcommand)]
enum Action {
    /// Run this repository's correctness, formatter and linter gate.
    Gate,
    /// Scan all new commits since the trusted adoption baseline and sign a receipt.
    Check {
        #[arg(long, default_value = "HEAD")]
        head: String,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Verify a receipt without invoking scanners.
    Verify {
        #[arg(long, default_value = "HEAD")]
        head: String,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long)]
        receipt: PathBuf,
    },
    /// Verify retained evidence, optionally push, and publish its bot check.
    Publish {
        #[arg(long, default_value = "HEAD")]
        head: String,
        #[arg(long)]
        tag: Vec<String>,
        #[arg(long)]
        receipt: PathBuf,
        #[arg(long)]
        remote_ref: Option<String>,
    },
    /// Install coordinated hooks; retire an old pre-push guard only by exact digest.
    Install {
        #[arg(long)]
        retire_pre_push_sha256: Option<String>,
    },
    /// Report findings in the baseline tree separately from new-change admission.
    Audit {
        #[arg(long)]
        output: PathBuf,
    },
    /// Generate a protected Ed25519 key. An administrator must enroll the printed public key.
    Keygen {
        #[arg(long)]
        output: PathBuf,
    },
    /// Run a Git operation under the existing organization bot App.
    Bot {
        #[arg(last = true, required = true)]
        args: Vec<String>,
    },
    /// Run GitHub delivery commands with the bot token confined to the child environment.
    Gh {
        #[arg(last = true, required = true)]
        args: Vec<String>,
    },
    /// Invoke a bot-authenticated GitHub API operation using JSON files, never tokens in argv.
    Api {
        #[arg(long)]
        method: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        input: Option<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify reusable evidence or run scanners on candidate Git objects in a fresh bare store.
    Ci {
        #[arg(long, env = "GITHUB_EVENT_PATH")]
        event: PathBuf,
        #[arg(long)]
        objects: PathBuf,
    },
    /// Refuse a file that breaks a private rule, for content published outside Git.
    ScanText {
        #[arg(required = true)]
        path: Vec<PathBuf>,
    },
    /// Edit the trusted policy itself.
    Policy {
        #[command(subcommand)]
        action: PolicyAction,
    },
    /// Download and verify the pinned published Gitleaks archive for this platform.
    Bootstrap {
        #[arg(long)]
        directory: PathBuf,
    },
}

#[derive(Subcommand)]
enum PolicyAction {
    /// Admit reported findings as exceptions, appended to the policy for review as a diff.
    Except {
        /// A findings report, as written by `audit --output`.
        #[arg(long)]
        findings: PathBuf,
        /// Keep only these rules. Default: every rule in the report.
        #[arg(long)]
        rule: Vec<String>,
        /// Keep only these locations. Default: every location in the report.
        #[arg(long)]
        location: Vec<String>,
        /// Bind the content but not the line, so an insertion above does not
        /// re-break the exception.
        #[arg(long)]
        any_line: bool,
        /// Bind the location but not the content, for a tree regenerated on every
        /// build where no digest survives the next run.
        #[arg(long)]
        any_content: bool,
    },
}

fn main() {
    let result = if let Some(name) = hooks::invoked() {
        hooks::run(&name, &std::env::args().skip(1).collect::<Vec<_>>())
    } else {
        execute(Args::parse())
    };
    if let Err(error) = result {
        eprintln!("b10x-gates: {error}");
        std::process::exit(1);
    }
}

fn execute(args: Args) -> Result<()> {
    if matches!(args.command, Action::Gate) {
        let scanner = args
            .gitleaks
            .unwrap_or(policy::root()?.join("bin/gitleaks"));
        if !scanner.is_file() {
            bootstrap(scanner.parent().context("scanner directory missing")?)?;
        }
        let scanner = fs::canonicalize(scanner)?;
        for command in [
            vec!["test", "--locked"],
            vec!["fmt", "--all", "--check"],
            vec![
                "clippy",
                "--all-targets",
                "--locked",
                "--",
                "-D",
                "warnings",
            ],
        ] {
            let status = std::process::Command::new("cargo")
                .current_dir(&args.repo)
                .args(command)
                .env("B10X_GATES_GITLEAKS", &scanner)
                .status()?;
            ensure!(status.success(), "Gates correctness gate failed");
        }
        return Ok(());
    }
    if let Action::Keygen { output } = &args.command {
        println!("{}", evidence::generate_key(output)?);
        return Ok(());
    }
    if let Action::Bootstrap { directory } = &args.command {
        bootstrap(directory)?;
        println!("pinned Gitleaks installed");
        return Ok(());
    }
    if let Action::Bot { args: command } = &args.command {
        return Github::bot()?.git(&args.repo, command);
    }
    if let Action::Gh { args: command } = &args.command {
        // A pull request body, an issue comment and a release note are published
        // content that no Git hook ever sees. Scan before the child is spawned.
        // An option that names a file publishes the file, not its path. Scan what
        // is sent; a scratch path under the home directory is not the content.
        const FILE_OPTIONS: [&str; 3] = ["--body-file", "--notes-file", "--input"];
        let matchers = matchers(args.policy.as_deref())?;
        let mut previous: Option<&str> = None;
        for (i, argument) in command.iter().enumerate() {
            let named = previous.is_some_and(|p| FILE_OPTIONS.contains(&p));
            let bytes = if named {
                fs::read(argument).with_context(|| format!("argument {} unreadable", i + 1))?
            } else {
                argument.as_bytes().to_vec()
            };
            refuse(
                &matchers,
                &if named {
                    format!("argument {}, the file it names,", i + 1)
                } else {
                    format!("argument {}", i + 1)
                },
                &bytes,
            )?;
            previous = Some(argument);
        }
        return Github::bot()?.gh(&args.repo, command);
    }
    if let Action::Api {
        method,
        path,
        input,
        output,
    } = &args.command
    {
        let raw = input.as_ref().map(fs::read).transpose()?;
        if let Some(raw) = &raw {
            refuse(
                &matchers(args.policy.as_deref())?,
                &input
                    .as_ref()
                    .map_or_else(String::new, |p| p.display().to_string()),
                raw,
            )?;
        }
        let body = raw
            .map(|v| serde_json::from_slice::<serde_json::Value>(&v))
            .transpose()?;
        let response = Github::bot()?.api(method.parse()?, path, body.as_ref())?;
        policy::private_write(output, &serde_json::to_vec(&response)?)?;
        println!("bot API operation completed; response retained locally");
        return Ok(());
    }
    if let Action::ScanText { path } = &args.command {
        let matchers = matchers(args.policy.as_deref())?;
        for file in path {
            refuse(&matchers, &file.display().to_string(), &fs::read(file)?)?;
        }
        println!("{} file(s) carry no private rule", path.len());
        return Ok(());
    }
    let root = policy::root()?;
    let policy_path = args.policy.unwrap_or_else(|| root.join("policy.json"));
    let key_path = args.key.unwrap_or_else(|| root.join("signing-key"));
    let scanner_path = args.gitleaks.unwrap_or_else(|| root.join("bin/gitleaks"));
    let policy = if matches!(args.command, Action::Ci { .. }) {
        match std::env::var("B10X_GATES_POLICY_JSON") {
            Ok(bytes) => Policy::parse(bytes.as_bytes())?,
            Err(_) => Policy::load(&policy_path)?,
        }
    } else {
        Policy::load(&policy_path)?
    };
    let mut scanner = Gitleaks {
        binary: scanner_path.clone(),
    };
    if let Action::Ci { event, objects } = &args.command {
        let (_, candidate) = delivery::ci_candidate(&policy, event, objects)?;
        let token = std::env::var("GITHUB_TOKEN").context("workflow token unavailable")?;
        let github = Github::from_token(token)?;
        let receipts = github
            .receipts(&candidate.binding.repository, &candidate.binding.head)
            .unwrap_or_default();
        let valid = receipts
            .iter()
            .find(|r| evidence::verify(&policy, &candidate, r).is_ok());
        let reused = evidence::reuse_or_scan(&policy, &candidate, valid, &mut scanner)?;
        println!(
            "common checks passed; evidence_reused={reused}; scanner_invocations={}",
            if reused { 0 } else { 1 }
        );
        return Ok(());
    }
    if let Action::Policy { action } = &args.command {
        let PolicyAction::Except {
            findings,
            rule,
            location,
            any_line,
            any_content,
        } = action;
        let reported: Vec<scan::Finding> = serde_json::from_slice(&fs::read(findings)?)
            .map_err(|_| anyhow::anyhow!("findings report format invalid"))?;
        let repository = args.repository.context("--repository is required")?;
        policy.repository(&repository)?;
        let mut edited = policy.clone();
        let mut added = 0usize;
        for finding in reported {
            if !rule.is_empty() && !rule.contains(&finding.rule) {
                continue;
            }
            if !location.is_empty() && !location.contains(&finding.location) {
                continue;
            }
            let exception = policy::Exception {
                repository: repository.clone(),
                rule: finding.rule,
                location: finding.location,
                content_sha256: if *any_content {
                    String::new()
                } else {
                    finding.content_sha256
                },
                line: if *any_line { 0 } else { finding.line },
            };
            if edited.exceptions.iter().any(|e| {
                e.repository == exception.repository
                    && e.rule == exception.rule
                    && e.location == exception.location
                    && e.content_sha256 == exception.content_sha256
                    && e.line == exception.line
            }) {
                continue;
            }
            edited.exceptions.push(exception);
            added += 1;
        }
        edited.exceptions.sort_by(|a, b| {
            (&a.repository, &a.location, a.line, &a.rule).cmp(&(
                &b.repository,
                &b.location,
                b.line,
                &b.rule,
            ))
        });
        edited.validate()?;
        let mut bytes = serde_json::to_vec_pretty(&edited)?;
        bytes.push(b'\n');
        policy::private_write(&policy_path, &bytes)?;
        println!("{added} exception(s) added; review the policy diff before committing");
        return Ok(());
    }
    let repository = args.repository.context("--repository is required")?;
    policy.repository(&repository)?;
    if let Action::Install {
        retire_pre_push_sha256,
    } = &args.command
    {
        hooks::install(
            &args.repo,
            hooks::Config {
                repository,
                policy: policy_path,
                key: key_path,
                scanner: scanner_path,
                previous: BTreeMap::new(),
                retired_pre_push_digest: None,
                installed_version: String::new(),
            },
            retire_pre_push_sha256.as_deref(),
        )?;
        println!("coordinated hooks installed");
        return Ok(());
    }
    let git = Git::new(&args.repo)?;
    if let Action::Audit { output } = &args.command {
        let units = git.historical(&policy.repository(&repository)?.baseline)?;
        let report = scan::run(&policy, &repository, &units, &mut scanner)?;
        policy::private_write(output, &serde_json::to_vec(&report.findings)?)?;
        println!(
            "historical baseline: {} finding(s); detailed report retained locally",
            report.findings.len()
        );
        return Ok(());
    }
    let (head, tags, receipt_path) = match &args.command {
        Action::Check { head, tag, receipt }
        | Action::Verify { head, tag, receipt }
        | Action::Publish {
            head, tag, receipt, ..
        } => (head, tag, receipt),
        _ => unreachable!(),
    };
    let head = git.resolve(head)?;
    let candidate = git.candidate(&policy, &repository, &head, tags)?;
    match &args.command {
        Action::Check { .. } => {
            let retained = fs::read(receipt_path)
                .ok()
                .and_then(|v| serde_json::from_slice::<Receipt>(&v).ok());
            if retained
                .as_ref()
                .is_some_and(|r| evidence::verify(&policy, &candidate, r).is_ok())
            {
                println!("valid retained receipt reused; scanner_invocations=0");
            } else {
                let key = evidence::read_key(&key_path)?;
                let receipt = evidence::check(&policy, &candidate, &key, &mut scanner)?;
                policy::private_write(receipt_path, &serde_json::to_vec(&receipt)?)?;
                println!("common checks passed; signed receipt retained");
            }
        }
        Action::Verify { .. } | Action::Publish { .. } => {
            let receipt: Receipt = serde_json::from_slice(&fs::read(receipt_path)?)
                .map_err(|_| anyhow::anyhow!("receipt format invalid"))?;
            evidence::verify(&policy, &candidate, &receipt)?;
            if let Action::Publish { remote_ref, .. } = &args.command {
                let github = Github::bot()?;
                git.verify_bot(&candidate.binding.commits)?;
                if let Some(remote_ref) = remote_ref {
                    ensure!(
                        remote_ref.starts_with("refs/heads/")
                            && !remote_ref.contains(':')
                            && !remote_ref.contains(".."),
                        "publish requires a branch ref"
                    );
                    github.git(
                        &args.repo,
                        &[
                            "push".into(),
                            format!("https://github.com/{repository}.git"),
                            format!("{head}:{remote_ref}"),
                        ],
                    )?;
                }
                println!("{}", github.publish(&policy, &candidate, &receipt)?);
            } else {
                println!("receipt valid; scanner_invocations=0");
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

/// The private rules alone, for the verbs that publish rather than commit. A missing
/// policy is a refusal, never an unscanned send.
fn matchers(path: Option<&std::path::Path>) -> Result<scan::Matchers> {
    let path = match path {
        Some(path) => path.to_path_buf(),
        None => policy::root()?.join("policy.json"),
    };
    scan::Matchers::build(&Policy::load(&path)?)
}

/// Refuse without echoing the matched text, as every other scanner here does.
fn refuse(matchers: &scan::Matchers, what: &str, bytes: &[u8]) -> Result<()> {
    let broken = matchers.text(bytes);
    ensure!(
        broken.is_empty(),
        "{what} breaks {} private rule(s): {}; private details remain local",
        broken.len(),
        broken
            .iter()
            .take(6)
            .map(|(line, rule)| format!("line {line} {rule}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    Ok(())
}

fn bootstrap(directory: &std::path::Path) -> Result<()> {
    let (platform, checksum) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => (
            "linux_x64",
            "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
        ),
        ("linux", "aarch64") => (
            "linux_arm64",
            "e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080",
        ),
        ("macos", "x86_64") => (
            "darwin_x64",
            "dfe101a4db2255fc85120ac7f3d25e4342c3c20cf749f2c20a18081af1952709",
        ),
        ("macos", "aarch64") => (
            "darwin_arm64",
            "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5",
        ),
        _ => anyhow::bail!(
            "bootstrap supports Linux and macOS; use the pinned upstream binary on other platforms"
        ),
    };
    let version = b10x_gates::GITLEAKS_VERSION;
    let url = format!(
        "https://github.com/gitleaks/gitleaks/releases/download/v{version}/gitleaks_{version}_{platform}.tar.gz"
    );
    let bytes = reqwest::blocking::Client::builder()
        .https_only(true)
        .timeout(std::time::Duration::from_secs(120))
        .build()?
        .get(url)
        .send()?
        .error_for_status()?
        .bytes()?;
    ensure!(
        b10x_gates::digest(&bytes) == checksum,
        "published scanner checksum mismatch"
    );
    fs::create_dir_all(directory)?;
    let temporary = tempfile::tempdir_in(directory)?;
    let archive = temporary.path().join("scanner.tar.gz");
    fs::write(&archive, bytes)?;
    let output = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(temporary.path())
        .arg("gitleaks")
        .output()?;
    ensure!(output.status.success(), "scanner archive extraction failed");
    fs::rename(
        temporary.path().join("gitleaks"),
        directory.join("gitleaks"),
    )?;
    Ok(())
}
