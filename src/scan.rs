//! Scanners return only rule coordinates, never matched text.
use crate::{GITLEAKS_VERSION, RULES, digest, git::Unit, policy::Policy};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_yaml::Value;
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    ops::Range,
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
                    inspected: if rule == "commit-authorship" {
                        units
                            .iter()
                            .filter(|u| u.location.starts_with("commit:"))
                            .count()
                    } else if rule.starts_with("workflow-") {
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

/// The private rules, compiled once. Literals are escaped; patterns are not.
pub struct Matchers {
    private: Vec<regex::bytes::Regex>,
    /// One per literal long enough to be unambiguous: the same literal with an
    /// optional line break allowed between every character, so a soft-wrapped
    /// paragraph or a reflowed table cell cannot split a term past a line scanner.
    wrapped: Vec<regex::bytes::Regex>,
    allow: Vec<regex::bytes::Regex>,
    homes: regex::bytes::Regex,
    format: regex::bytes::Regex,
    /// A JSON array of hex strings under a `"components"` key, the shape ESS
    /// writes an absolute path in, and one element of it.
    components: regex::bytes::Regex,
    component: regex::bytes::Regex,
}

/// Shortest literal that is re-checked across line breaks. Below it the joined
/// form matches too much by accident.
const WRAP_MINIMUM: usize = 8;

/// A pattern that matches this, or the empty input, matches everything worth
/// scanning, and is refused rather than silently disabling a rule.
const CANARY: &[u8] = b"the quick brown fox jumps over the lazy dog 0123456789";

fn compile(source: &str) -> Result<regex::bytes::Regex> {
    regex::bytes::RegexBuilder::new(source)
        .case_insensitive(true)
        .size_limit(1 << 20)
        .build()
        .map_err(|_| anyhow::anyhow!("private pattern invalid"))
}

/// True when a rule is too broad to be a rule.
pub fn matches_everything(source: &str) -> bool {
    compile(source).is_ok_and(|r| r.is_match(b"") || r.is_match(CANARY))
}

/// The literal, with an optional line break permitted between every character.
fn wrapped_source(literal: &str) -> String {
    let mut out = String::new();
    for (i, ch) in literal.chars().enumerate() {
        if i > 0 {
            out.push_str(r"(?:-?[ \t]*\r?\n[ \t>|*#]*)?");
        }
        out.push_str(&regex::escape(&ch.to_string()));
    }
    out
}

impl Matchers {
    pub fn build(policy: &Policy) -> Result<Self> {
        for pattern in policy
            .forbidden_patterns
            .iter()
            .chain(&policy.allow_patterns)
        {
            ensure!(
                !matches_everything(pattern),
                "private rule matches everything"
            );
        }
        ensure!(
            policy
                .allow_patterns
                .iter()
                .all(|v| v.contains("(?P<admit>") || v.contains("(?<admit>")),
            "an allowance must name what it admits with (?P<admit>...)"
        );
        let private = policy
            .forbidden_literals
            .iter()
            .map(|v| compile(&regex::escape(v)))
            .chain(policy.forbidden_patterns.iter().map(|v| compile(v)))
            .collect::<Result<Vec<_>>>()?;
        let wrapped = policy
            .forbidden_literals
            .iter()
            .filter(|v| v.chars().count() >= WRAP_MINIMUM)
            .map(|v| compile(&wrapped_source(v)))
            .collect::<Result<Vec<_>>>()?;
        let allow = policy
            .allow_patterns
            .iter()
            .map(|v| compile(v))
            .collect::<Result<Vec<_>>>()?;
        // The boundary excludes what a hostname or a relative path ends with, so
        // `example.com/home/x`, `../home/x` and `src/home/mod.rs` stay clear while a
        // backtick, a table pipe, an emphasis marker, a diff `-`, an underscore,
        // `file://` and an invalid byte all open it. `/Users/` is the macOS spelling
        // and is matched case-sensitively: lowercase `/users/...` is a REST route.
        // The first segment is a user directory: either it is followed by `/`, or it
        // ends the reference. A dotted segment that ends the reference is a file, so
        // a markdown link to an index page and a REST route ending in a filename are
        // routes, not paths.
        let homes = regex::bytes::Regex::new(
            r#"(?im)(?:^|(?-u:[^a-zA-Z0-9.\\]))(?:/home/|(?-i:/Users/)|[a-z]:[\\/]+(?:users|documents and settings)[\\/]+|(?-u:\\)(?-u:\\)[a-z0-9._-]+(?-u:\\)users(?-u:\\))(?:[a-z0-9_][a-z0-9_.-]*[/\\]|[a-z0-9_][a-z0-9_-]*(?:$|[^a-z0-9_.\\-]))"#,
        )?;
        // Format characters carry no meaning in a term and are what a word processor
        // or a wiki paste inserts. They are removed before matching, never reported.
        let format = regex::bytes::Regex::new(r"\p{Cf}")?;
        // Compact or pretty-printed, and with its quotes and line breaks escaped
        // when the record is itself carried inside a JSON string. The encoding
        // marker beside the array is not required: a renamed one must not hide it.
        let space = r"(?:[ \t\r\n]|\\+[nrt])*";
        let quote = r#"\\*""#;
        let item = format!("{quote}[0-9A-Fa-f]*{quote}");
        let components = regex::bytes::Regex::new(&format!(
            r"(?-u){quote}components{quote}{space}:{space}\[(?P<list>{space}{item}(?:{space},{space}{item})*{space})\]"
        ))?;
        let component =
            regex::bytes::Regex::new(&format!("(?-u){quote}(?P<hex>[0-9A-Fa-f]*){quote}"))?;
        Ok(Self {
            private,
            wrapped,
            allow,
            homes,
            format,
            components,
            component,
        })
    }

    /// Admitted byte ranges, merged into a disjoint ascending cover so containment
    /// is a binary search rather than a scan of every span on every occurrence.
    /// An allowance admits only what its `(?P<admit>…)` group captures, so the text
    /// around a citation — a markdown link label, a query string, a quoted comment —
    /// is never admitted with it.
    fn admitted(&self, bytes: &[u8]) -> Vec<(usize, usize)> {
        let mut spans: Vec<(usize, usize)> = self
            .allow
            .iter()
            .flat_map(|a| {
                a.captures_iter(bytes)
                    .filter_map(|c| c.name("admit").map(|m| (m.start(), m.end())))
            })
            .collect();
        spans.sort_unstable();
        let mut merged: Vec<(usize, usize)> = Vec::with_capacity(spans.len());
        for (s, e) in spans {
            match merged.last_mut() {
                Some(last) if s <= last.1 => last.1 = last.1.max(e),
                _ => merged.push((s, e)),
            }
        }
        merged
    }

    fn covered(cover: &[(usize, usize)], start: usize, end: usize) -> bool {
        let i = cover.partition_point(|&(s, _)| s <= start);
        i > 0 && cover[i - 1].1 >= end
    }

    /// Rules one line breaks. An allowance admits only an occurrence its match
    /// *contains*: a line carrying an admitted URL and a forbidden prose use is
    /// still refused. Allowances never reach `personal-paths` — they exist to admit
    /// a citation of a private identifier, never a machine-local path.
    pub fn line(&self, bytes: &[u8]) -> Vec<&'static str> {
        let cover = self.admitted(bytes);
        let uncovered = |pattern: &regex::bytes::Regex, bytes: &[u8], apply: bool| {
            pattern
                .find_iter(bytes)
                .any(|m| !apply || !Self::covered(&cover, m.start(), m.end()))
        };
        let mut rules = Vec::new();
        let stripped = self.strip(bytes);
        if self.private.iter().any(|p| {
            uncovered(p, bytes, true) || stripped.as_ref().is_some_and(|b| uncovered(p, b, false))
        }) {
            rules.push("private-identifiers");
        }
        if self.personal(bytes) {
            rules.push("personal-paths");
        }
        rules
    }

    /// The `personal-paths` rule, for a line or a decoded path alike.
    fn personal(&self, bytes: &[u8]) -> bool {
        self.homes.is_match(bytes) || self.strip(bytes).is_some_and(|b| self.homes.is_match(&b))
    }

    /// Every `"components"` array whose decoded path is a personal path: the line
    /// its key starts on, and the byte range of every line it spans, the breaks
    /// between them included. Each element is the hex of one segment with the
    /// leading `/` stripped, so the path text never appears for a line scanner to
    /// see. An element that does not decode contributes its own text.
    pub fn hex_paths(&self, unit: &[u8]) -> Vec<(usize, Range<usize>)> {
        let mut spans = Vec::new();
        // `line` is the line `cursor` is on and `begin` where that line starts;
        // `end` is the first line break at or after the previous hit, or the end
        // of the unit. All three only move forward.
        let (mut cursor, mut line, mut begin, mut end) = (0, 1, 0, 0);
        for array in self.components.captures_iter(unit) {
            let mut path = Vec::new();
            for item in self.component.captures_iter(&array["list"]) {
                let hex = &item["hex"];
                path.push(b'/');
                path.extend(hex::decode(hex).unwrap_or_else(|_| hex.to_vec()));
            }
            if !self.personal(&path) {
                continue;
            }
            let whole = array.get(0).expect("whole match");
            carry(unit, cursor..whole.start(), &mut line, &mut begin);
            let (first, start) = (line, begin);
            carry(unit, whole.range(), &mut line, &mut begin);
            cursor = whole.end();
            if end < cursor {
                end = unit[cursor..]
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(unit.len(), |i| cursor + i);
            }
            spans.push((first, start..end));
        }
        spans
    }

    /// The line with Unicode format characters removed, when it has any. `None`
    /// when the line is plain ASCII, which is the common case and needs no copy.
    fn strip(&self, bytes: &[u8]) -> Option<Vec<u8>> {
        if bytes.is_ascii() {
            return None;
        }
        let out = self.format.replace_all(bytes, &b""[..]).into_owned();
        (out != bytes).then_some(out)
    }

    /// Lines where a literal is present only once the unit's line breaks are
    /// ignored. Reported against the line the occurrence starts on.
    pub fn wrapped_lines(&self, unit: &[u8]) -> Vec<usize> {
        let mut lines: Vec<usize> = Vec::new();
        // Matches of one pattern arrive in order, so the line count carries
        // forward instead of being recounted from the start for every match.
        for wrapped in &self.wrapped {
            let (mut cursor, mut line) = (0, 1);
            for m in wrapped.find_iter(unit) {
                if !unit[m.start()..m.end()].contains(&b'\n') {
                    continue;
                }
                line += newlines(&unit[cursor..m.start()]);
                cursor = m.start();
                lines.push(line);
            }
        }
        lines.sort_unstable();
        lines.dedup();
        lines
    }

    /// Every broken rule in a block of text, with its line number. Used by the
    /// delivery verbs, which publish content Git hooks never see.
    pub fn text(&self, bytes: &[u8]) -> Vec<(usize, &'static str)> {
        let mut broken: Vec<(usize, &'static str)> = bytes
            .split(|v| *v == b'\n')
            .enumerate()
            .flat_map(|(i, line)| self.line(line).into_iter().map(move |r| (i + 1, r)))
            .collect();
        let mut seen: HashSet<(usize, &'static str)> = broken.iter().copied().collect();
        for line in self.wrapped_lines(bytes) {
            if seen.insert((line, "private-identifiers")) {
                broken.push((line, "private-identifiers"));
            }
        }
        for (line, _) in self.hex_paths(bytes) {
            if seen.insert((line, "personal-paths")) {
                broken.push((line, "personal-paths"));
            }
        }
        broken.sort_unstable();
        broken
    }
}

fn newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|b| **b == b'\n').count()
}

/// Moves a line position across `skipped`: counts its line breaks into `line`,
/// and sets `begin` to just after the last of them.
fn carry(unit: &[u8], skipped: Range<usize>, line: &mut usize, begin: &mut usize) {
    let from = skipped.start;
    let skipped = &unit[skipped];
    *line += newlines(skipped);
    if let Some(i) = skipped.iter().rposition(|b| *b == b'\n') {
        *begin = from + i + 1;
    }
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
    let matchers = Matchers::build(policy)?;
    for unit in units {
        // A line already present in this location before the change was not
        // introduced by it. This is what makes an adoption baseline mean anything
        // for a file that is edited rather than left alone.
        let inherited: std::collections::HashSet<&[u8]> = unit
            .inherited
            .as_deref()
            .map(|b| b.split(|v| *v == b'\n').collect())
            .unwrap_or_default();
        // A compiled artifact, an archive or an image carries no prose. Gitleaks
        // still reads it; the private literal and path rules do not.
        let binary = unit.bytes.iter().take(8192).any(|b| *b == 0);
        // Sets, not lists: a unit can carry a finding on every one of its lines,
        // and each later pass asks whether a line already has one.
        let mut reported: HashSet<usize> = HashSet::new();
        let mut paths: HashSet<usize> = HashSet::new();
        for (line, bytes) in unit.bytes.split(|v| *v == b'\n').enumerate() {
            if binary || inherited.contains(bytes) {
                continue;
            }
            for rule in matchers.line(bytes) {
                if rule == "private-identifiers" {
                    reported.insert(line + 1);
                }
                if finding(policy, repository, &mut report, unit, line + 1, rule, bytes)
                    && rule == "personal-paths"
                {
                    paths.insert(line + 1);
                }
            }
        }
        // A path written as hex-encoded segments carries no path text. It is
        // reported on the line its key starts on and bound to every line it spans,
        // so it is inherited only when all of them are, and an exception for the
        // key line alone cannot admit different components.
        if !binary {
            for (first, span) in matchers.hex_paths(&unit.bytes) {
                let span = &unit.bytes[span];
                if paths.contains(&first)
                    || span.split(|v| *v == b'\n').all(|v| inherited.contains(v))
                {
                    continue;
                }
                if finding(
                    policy,
                    repository,
                    &mut report,
                    unit,
                    first,
                    "personal-paths",
                    span,
                ) {
                    paths.insert(first);
                }
            }
        }
        // A literal a soft wrap split over two lines is invisible to a line scanner.
        // Its lines arrive ascending, so one forward walk over the unit finds each.
        let mut rest = unit.bytes.split(|v| *v == b'\n');
        let mut taken = 0;
        for line in if binary {
            Vec::new()
        } else {
            matchers.wrapped_lines(&unit.bytes)
        } {
            if reported.contains(&line) {
                continue;
            }
            let bytes = rest.nth(line - 1 - taken).unwrap_or(&[]);
            taken = line;
            finding(
                policy,
                repository,
                &mut report,
                unit,
                line,
                "private-identifiers",
                bytes,
            );
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
        let unit = &units[leak.unit];
        // The same inheritance: a secret the previous version of this file already
        // carried on that exact line is not introduced by this change.
        let line = unit.bytes.split(|v| *v == b'\n').nth(leak.line - 1);
        if let (Some(line), Some(previous)) = (line, unit.inherited.as_deref())
            && previous.split(|v| *v == b'\n').any(|v| v == line)
        {
            continue;
        }
        finding(
            policy,
            repository,
            &mut report,
            unit,
            leak.line,
            "secrets",
            &unit.bytes,
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
) -> bool {
    // Historical privacy findings are bounded to unchanged exact lines. Secret and
    // workflow exceptions bind the whole unit because those rules can span lines.
    let content_sha256 = digest(content);
    if policy.exceptions.iter().any(|e| {
        e.covers(repository, rule, &unit.location)
            && (e.content_sha256.is_empty() || e.content_sha256 == content_sha256)
            && (e.line == 0 || e.line == line)
    }) {
        return false;
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
    true
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
