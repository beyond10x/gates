//! Scanners return only rule coordinates, never matched text.
use crate::{GITLEAKS_VERSION, RULES, digest, git::Unit, policy::Policy};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RuleResult {
    pub inspected: usize,
    pub findings: usize,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Finding {
    pub rule: String,
    pub location: String,
    pub line: usize,
    pub content_sha256: String,
}

pub struct Report {
    pub results: BTreeMap<String, RuleResult>,
    pub findings: Vec<Finding>,
}

impl Report {
    pub fn require_success(&self) -> Result<()> {
        ensure!(
            self.findings.is_empty(),
            "common checks failed: {} finding(s); private details remain local",
            self.findings.len()
        );
        Ok(())
    }
}

pub struct SecretFinding {
    pub unit: usize,
    pub line: usize,
}

pub trait SecretScanner {
    fn scan(&mut self, units: &[Unit]) -> Result<Vec<SecretFinding>>;
}

pub struct Gitleaks {
    pub binary: PathBuf,
}

impl SecretScanner for Gitleaks {
    fn scan(&mut self, units: &[Unit]) -> Result<Vec<SecretFinding>> {
        let binary =
            fs::canonicalize(&self.binary).context("pinned Gitleaks binary unavailable")?;
        let dir = tempfile::tempdir()?;
        let source = dir.path().join("input");
        fs::create_dir(&source)?;
        for (i, unit) in units.iter().enumerate() {
            fs::write(source.join(i.to_string()), &unit.bytes)?;
        }
        let config = dir.path().join("scanner.toml");
        fs::write(&config, "[extend]\nuseDefault = true\n")?;
        let ignore = dir.path().join("empty-ignore");
        fs::write(&ignore, "")?;
        let report = dir.path().join("report.json");
        let command = || {
            let mut c = Command::new(&binary);
            c.current_dir(dir.path())
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .stdin(Stdio::null());
            c
        };
        let version = command()
            .arg("version")
            .output()
            .context("Gitleaks version unavailable")?;
        ensure!(
            version.status.success()
                && String::from_utf8_lossy(&version.stdout).trim() == GITLEAKS_VERSION,
            "Gitleaks version mismatch"
        );
        let output = command()
            .arg("dir")
            .arg(&source)
            .arg("--config")
            .arg(&config)
            .arg("--gitleaks-ignore-path")
            .arg(&ignore)
            .args([
                "--ignore-gitleaks-allow",
                "--redact=100",
                "--no-banner",
                "--no-color",
                "--log-level=error",
                "--max-target-megabytes=0",
                "--max-decode-depth=5",
                "--timeout=180",
                "--report-format=json",
            ])
            .arg("--report-path")
            .arg(&report)
            .output()
            .context("Gitleaks execution failed")?;
        ensure!(
            matches!(output.status.code(), Some(0 | 1)),
            "Gitleaks failed; scanner output withheld"
        );
        #[derive(Deserialize)]
        struct Leak {
            #[serde(rename = "File")]
            file: String,
            #[serde(rename = "StartLine")]
            line: usize,
        }
        let leaks: Vec<Leak> =
            serde_json::from_slice(&fs::read(report).context("Gitleaks report missing")?)
                .map_err(|_| anyhow::anyhow!("Gitleaks report invalid"))?;
        ensure!(
            output.status.success() == leaks.is_empty(),
            "Gitleaks result contradicts its exit status"
        );
        leaks
            .into_iter()
            .map(|leak| {
                let path = PathBuf::from(leak.file);
                let unit: usize = path
                    .file_name()
                    .and_then(|v| v.to_str())
                    .context("scanner coordinate missing")?
                    .parse()
                    .context("scanner coordinate invalid")?;
                ensure!(
                    unit < units.len() && leak.line > 0,
                    "scanner coordinate out of bounds"
                );
                Ok(SecretFinding {
                    unit,
                    line: leak.line,
                })
            })
            .collect()
    }
}

pub fn expected_results(units: &[Unit]) -> BTreeMap<String, RuleResult> {
    RULES
        .into_iter()
        .map(|rule| {
            (
                rule.to_owned(),
                RuleResult {
                    inspected: if rule.starts_with("workflow-") {
                        units.iter().filter(|u| u.workflow).count()
                    } else {
                        units.len()
                    },
                    findings: 0,
                },
            )
        })
        .collect()
}

pub fn run(
    policy: &Policy,
    repository: &str,
    units: &[Unit],
    scanner: &mut dyn SecretScanner,
) -> Result<Report> {
    policy.validate()?;
    policy.repository(repository)?;
    let mut report = Report {
        results: expected_results(units),
        findings: Vec::new(),
    };
    let private = policy
        .forbidden_literals
        .iter()
        .map(|literal| {
            regex::bytes::RegexBuilder::new(&regex::escape(literal))
                .case_insensitive(true)
                .build()
        })
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| anyhow::anyhow!("private pattern invalid"))?;
    let homes = regex::bytes::Regex::new(
        r#"(?im)(?:^|[\s="'(>:])(?:/home/|/users/|[a-z]:[\\/]+(?:users|documents and settings)[\\/]+)[a-z0-9_][a-z0-9_.-]*"#,
    )?;
    for unit in units {
        for (line, bytes) in unit.bytes.split(|v| *v == b'\n').enumerate() {
            if private.iter().any(|p| p.is_match(bytes)) {
                finding(
                    policy,
                    repository,
                    &mut report,
                    unit,
                    line + 1,
                    "private-identifiers",
                    bytes,
                );
            }
            if homes.is_match(bytes) {
                finding(
                    policy,
                    repository,
                    &mut report,
                    unit,
                    line + 1,
                    "personal-paths",
                    bytes,
                );
            }
        }
        if unit.workflow {
            let (pins, permissions) = workflow(&unit.bytes);
            if !pins {
                finding(
                    policy,
                    repository,
                    &mut report,
                    unit,
                    1,
                    "workflow-pins",
                    &unit.bytes,
                );
            }
            if !permissions {
                finding(
                    policy,
                    repository,
                    &mut report,
                    unit,
                    1,
                    "workflow-permissions",
                    &unit.bytes,
                );
            }
        }
    }
    for leak in scanner.scan(units)? {
        finding(
            policy,
            repository,
            &mut report,
            &units[leak.unit],
            leak.line,
            "secrets",
            &units[leak.unit].bytes,
        );
    }
    Ok(report)
}

fn finding(
    policy: &Policy,
    repository: &str,
    report: &mut Report,
    unit: &Unit,
    line: usize,
    rule: &str,
    content: &[u8],
) {
    // Historical privacy findings are bounded to unchanged exact lines. Secret and
    // workflow exceptions bind the whole unit because those rules can span lines.
    let content_sha256 = digest(content);
    if policy.exceptions.iter().any(|e| {
        e.repository == repository
            && e.rule == rule
            && e.location == unit.location
            && e.content_sha256 == content_sha256
            && e.line == line
    }) {
        return;
    }
    report
        .results
        .get_mut(rule)
        .expect("closed rule roster")
        .findings += 1;
    report.findings.push(Finding {
        rule: rule.into(),
        location: unit.location.clone(),
        line,
        content_sha256,
    });
}

fn workflow(bytes: &[u8]) -> (bool, bool) {
    let Ok(root) = serde_yaml::from_slice::<Value>(bytes) else {
        return (false, false);
    };
    let Some(map) = root.as_mapping() else {
        return (false, false);
    };
    let Some(jobs) = map.get("jobs").and_then(Value::as_mapping) else {
        return (false, false);
    };
    let declared = |value: Option<&Value>| {
        value.is_some_and(|v| v.as_mapping().is_some() || v.as_str() == Some("read-all"))
    };
    let permissions = declared(map.get("permissions"))
        || (!jobs.is_empty() && jobs.values().all(|job| declared(job.get("permissions"))));
    fn walk(value: &Value) -> bool {
        match value {
            Value::Mapping(map) => map.iter().all(|(k, v)| {
                if k.as_str() == Some("uses") {
                    v.as_str().is_some_and(|s| {
                        s.starts_with("./")
                            || s.rsplit_once('@').is_some_and(|(action, rev)| {
                                !action.contains("${{")
                                    && ((rev.len() == 40
                                        && rev.bytes().all(|b| b.is_ascii_hexdigit()))
                                        || (action.starts_with("docker://")
                                            && rev.strip_prefix("sha256:").is_some_and(|d| {
                                                d.len() == 64
                                                    && d.bytes().all(|b| b.is_ascii_hexdigit())
                                            })))
                            })
                    })
                } else {
                    walk(v)
                }
            }),
            Value::Sequence(seq) => seq.iter().all(walk),
            _ => true,
        }
    }
    (walk(&root), permissions)
}
