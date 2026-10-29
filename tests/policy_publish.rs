//! `b10x-gates policy publish` puts `origin/main:policy.json` of the policy repository into
//! the CI secrets (modelled as `gates.delivery.PublishPolicy` in
//! `ess/domains/delivery.yaml`). A fake `gh` on `PATH` records every call and the value it
//! was given on standard input; no real secret is ever written. Each test is named after the
//! outcome it holds.
use b10x_gates::{
    BOT_EMAIL, BOT_NAME,
    policy::{Exception, Policy, Repository},
};
use base64::Engine;
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const SLICED: &str = "example/sliced";
const OTHER: &str = "example/other";

fn git(root: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(root)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_AUTHOR_NAME", BOT_NAME)
        .env("GIT_AUTHOR_EMAIL", BOT_EMAIL)
        .env("GIT_COMMITTER_NAME", BOT_NAME)
        .env("GIT_COMMITTER_EMAIL", BOT_EMAIL)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "Git fixture failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().into()
}

fn exception(repository: &str, location: &str) -> Exception {
    Exception {
        repository: repository.into(),
        rule: "personal-paths".into(),
        location: location.into(),
        content_sha256: "0".repeat(64),
        line: 1,
    }
}

/// A policy whose exceptions belong to `SLICED` and `OTHER`, padded with `padding`
/// further `OTHER` exceptions to reach a size.
fn policy(nonce: &str, padding: usize) -> Policy {
    let mut exceptions = vec![exception(SLICED, "sliced.md"), exception(OTHER, "other.md")];
    exceptions.extend((0..padding).map(|i| exception(OTHER, &format!("generated/{i:06}.md"))));
    Policy {
        version: 2,
        nonce: nonce.into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: [SLICED, OTHER]
            .iter()
            .map(|r| {
                (
                    r.to_string(),
                    Repository {
                        id: "123".into(),
                        baseline: "0".repeat(40),
                    },
                )
            })
            .collect(),
        signers: BTreeMap::new(),
        exceptions,
    }
}

const NONCE: &str = "synthetic-policy-nonce-for-local-test-1234";

/// An origin holding one committed policy, a clone of it (the policy repository), a
/// state directory, and a fake `gh` that logs to `log/`.
struct Fixture {
    _origin: TempDir,
    clone: TempDir,
    scratch: TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self::with(&policy(NONCE, 0))
    }

    fn with(committed: &Policy) -> Self {
        let origin = tempfile::tempdir().unwrap();
        git(
            origin.path(),
            &["-c", "init.templateDir=", "init", "-q", "-b", "main"],
        );
        fs::write(
            origin.path().join("policy.json"),
            serde_json::to_vec_pretty(committed).unwrap(),
        )
        .unwrap();
        git(origin.path(), &["add", "policy.json"]);
        git(origin.path(), &["commit", "-q", "-m", "policy"]);
        let clone = tempfile::tempdir().unwrap();
        git(
            clone.path(),
            &[
                "-c",
                "init.templateDir=",
                "clone",
                "-q",
                origin.path().to_str().unwrap(),
                ".",
            ],
        );
        let scratch = tempfile::tempdir().unwrap();
        for dir in ["bin", "log", "state", "home"] {
            fs::create_dir(scratch.path().join(dir)).unwrap();
        }
        let gh = scratch.path().join("bin/gh");
        let log = scratch.path().join("log");
        fs::write(
            &gh,
            format!(
                "#!/bin/sh\n\
                 log='{log}'\n\
                 n=$(ls \"$log\" | grep -c args)\n\
                 printf '%s\\n' \"$@\" > \"$log/$n.args\"\n\
                 if [ \"$1 $2\" = 'secret set' ]; then\n\
                   [ -e \"$log/../fail-set\" ] && exit 1\n\
                   cat > \"$log/$n.value\"\n\
                   echo \"$5 $3\" >> \"$log/../secrets\"\n\
                 elif [ \"$1 $2\" = 'secret list' ]; then\n\
                   [ -e \"$log/../hide-list\" ] && exit 0\n\
                   [ \"$(cat \"$log/../hide-scope\" 2>/dev/null)\" = \"$4\" ] && exit 0\n\
                   grep \"^$4 \" \"$log/../secrets\" | cut -d' ' -f2 | sort -u \\\n\
                     | sed 's/$/\\t2026-10-14T00:00:00Z/'\n\
                 fi\n",
                log = log.display()
            ),
        )
        .unwrap();
        fs::set_permissions(&gh, fs::Permissions::from_mode(0o755)).unwrap();
        fs::write(scratch.path().join("secrets"), "").unwrap();
        let fixture = Self {
            _origin: origin,
            clone,
            scratch,
        };
        fixture.targets(&format!(
            r#"{{"organization": "example", "plain": true, "sliced": ["{SLICED}"]}}"#
        ));
        fixture
    }

    fn origin(&self) -> &Path {
        self._origin.path()
    }

    fn targets(&self, json: &str) {
        fs::write(self.scratch.path().join("targets.json"), json).unwrap();
    }

    fn marker(&self) -> PathBuf {
        self.scratch.path().join("state/published")
    }

    /// Commit `next` to the origin, so `origin/main` moves past the clone.
    fn commit(&self, next: &Policy) {
        fs::write(
            self.origin().join("policy.json"),
            serde_json::to_vec_pretty(next).unwrap(),
        )
        .unwrap();
        git(self.origin(), &["commit", "-q", "-am", "next policy"]);
    }

    fn publish(&self, extra: &[&str]) -> Output {
        let path = format!(
            "{}:{}",
            self.scratch.path().join("bin").display(),
            std::env::var("PATH").unwrap()
        );
        let targets = self.scratch.path().join("targets.json");
        let marker = self.marker();
        Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
            .args(["policy", "publish", "--policy-repository"])
            .arg(self.clone.path())
            .arg("--targets")
            .arg(&targets)
            .arg("--marker")
            .arg(&marker)
            .args(extra)
            .env_clear()
            .env("PATH", path)
            .env("HOME", self.scratch.path().join("home"))
            .env("XDG_CONFIG_HOME", self.scratch.path().join("home"))
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .output()
            .unwrap()
    }

    /// Every `gh` call, as (arguments, value given on standard input).
    fn calls(&self) -> Vec<(Vec<String>, Option<Vec<u8>>)> {
        let log = self.scratch.path().join("log");
        let mut calls = vec![];
        for n in 0.. {
            let args = log.join(format!("{n}.args"));
            if !args.exists() {
                break;
            }
            let value = fs::read(log.join(format!("{n}.value"))).ok();
            let args = fs::read_to_string(args)
                .unwrap()
                .lines()
                .map(String::from)
                .collect();
            calls.push((args, value));
        }
        calls
    }

    /// The value written for `secret` with the scope arguments `scope`.
    fn written(&self, secret: &str, scope: &[&str]) -> Vec<u8> {
        self.calls()
            .into_iter()
            .find(|(args, value)| {
                value.is_some()
                    && args.get(2).map(String::as_str) == Some(secret)
                    && scope.iter().all(|s| args.iter().any(|a| a == s))
            })
            .and_then(|(_, value)| value)
            .unwrap_or_else(|| panic!("{secret} {scope:?} was not written"))
    }

    fn sets(&self) -> usize {
        self.calls().iter().filter(|(_, v)| v.is_some()).count()
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn gunzip(value: &[u8]) -> Policy {
    let gzip = base64::engine::general_purpose::STANDARD
        .decode(value)
        .unwrap();
    let mut json = vec![];
    flate2::read::GzDecoder::new(gzip.as_slice())
        .read_to_end(&mut json)
        .unwrap();
    Policy::parse(&json).unwrap()
}

fn exception_repositories(value: &[u8]) -> Vec<String> {
    let policy = Policy::parse(value).unwrap();
    let mut repositories: Vec<_> = policy
        .exceptions
        .into_iter()
        .map(|e| e.repository)
        .collect();
    repositories.dedup();
    repositories
}

#[test]
fn planned_by_default() {
    let fixture = Fixture::new();
    let output = fixture.publish(&[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    let commit = git(fixture.origin(), &["rev-parse", "HEAD"]);
    assert!(out.contains(&commit), "{out}");
    assert!(out.contains("B10X_GATES_POLICY_GZ"), "{out}");
    assert!(out.contains(SLICED), "{out}");
    assert!(out.contains("bytes"), "{out}");
    assert_eq!(fixture.sets(), 0, "a dry run wrote a secret");
    assert!(!fixture.marker().exists(), "a dry run moved the marker");
}

#[test]
fn published_with_apply() {
    let fixture = Fixture::new();
    let output = fixture.publish(&["--apply"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let commit = git(fixture.origin(), &["rev-parse", "HEAD"]);
    let committed =
        Policy::parse(&fs::read(fixture.origin().join("policy.json")).unwrap()).unwrap();
    let gz = fixture.written("B10X_GATES_POLICY_GZ", &["--org", "example"]);
    assert_eq!(
        serde_json::to_value(gunzip(&gz)).unwrap(),
        serde_json::to_value(&committed).unwrap()
    );
    let org = fixture.written("B10X_GATES_POLICY", &["--org", "example"]);
    assert_eq!(exception_repositories(&org), vec![OTHER.to_string()]);
    let sliced = fixture.written("B10X_GATES_POLICY", &["--repo", SLICED]);
    assert_eq!(exception_repositories(&sliced), vec![SLICED.to_string()]);
    assert_eq!(fixture.sets(), 3);
    // Read back through `gh secret list`, then the marker names the commit.
    assert!(
        fixture
            .calls()
            .iter()
            .any(|(args, _)| args[..2] == ["secret", "list"])
    );
    assert_eq!(fs::read_to_string(fixture.marker()).unwrap().trim(), commit);
}

#[test]
fn only_origin_main_is_published() {
    let fixture = Fixture::new();
    // An uncommitted working-tree edit and a commit the clone has not fetched yet.
    fs::write(
        fixture.clone.path().join("policy.json"),
        serde_json::to_vec(&policy("working-tree-nonce-must-never-be-published", 0)).unwrap(),
    )
    .unwrap();
    let next = policy("origin-main-nonce-is-the-one-to-publish-0001", 0);
    fixture.commit(&next);
    let output = fixture.publish(&["--apply"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let gz = fixture.written("B10X_GATES_POLICY_GZ", &["--org", "example"]);
    assert_eq!(gunzip(&gz).nonce, next.nonce);
}

#[test]
fn unchanged_publishes_nothing() {
    let fixture = Fixture::new();
    assert!(fixture.publish(&["--apply"]).status.success());
    let before = fixture.sets();
    let output = fixture.publish(&["--apply"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(stdout(&output).contains("unchanged"), "{}", stdout(&output));
    assert_eq!(fixture.sets(), before);
}

#[test]
fn forced_publishes_unchanged() {
    let fixture = Fixture::new();
    assert!(fixture.publish(&["--apply"]).status.success());
    let before = fixture.sets();
    let output = fixture.publish(&["--apply", "--force"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(fixture.sets(), before + 3);
}

#[test]
fn oversized_publishes_nothing() {
    // The plain organization slice outgrows the limit; the compressed value does not.
    let fixture = Fixture::with(&policy(NONCE, 600));
    let output = fixture.publish(&["--apply"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("48000"), "{err}");
    assert!(err.contains("B10X_GATES_POLICY"), "{err}");
    assert_eq!(fixture.sets(), 0);
    assert!(!fixture.marker().exists());
}

#[test]
fn compressed_only_targets() {
    // Without plain secrets, a policy too large for them still publishes compressed.
    let fixture = Fixture::with(&policy(NONCE, 600));
    fixture.targets(r#"{"organization": "example"}"#);
    let output = fixture.publish(&["--apply"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(fixture.sets(), 1);
    fixture.written("B10X_GATES_POLICY_GZ", &["--org", "example"]);
}

#[test]
fn invalid_policy_publishes_nothing() {
    let fixture = Fixture::new();
    fs::write(fixture.origin().join("policy.json"), b"{\"version\": 2}").unwrap();
    git(fixture.origin(), &["commit", "-q", "-am", "broken"]);
    let output = fixture.publish(&["--apply"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("origin/main"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fixture.sets(), 0);
}

#[test]
fn unknown_target_field_refused() {
    let fixture = Fixture::new();
    fixture.targets(r#"{"organization": "example", "slices": ["example/sliced"]}"#);
    let output = fixture.publish(&[]);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("targets"), "{}", stderr(&output));
}

#[test]
fn write_failure_keeps_the_marker() {
    let fixture = Fixture::new();
    fs::write(fixture.scratch.path().join("fail-set"), "").unwrap();
    let output = fixture.publish(&["--apply"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("gh secret set"),
        "{}",
        stderr(&output)
    );
    assert!(!fixture.marker().exists());
}

#[test]
fn missing_read_back_keeps_the_marker() {
    let fixture = Fixture::new();
    fs::write(fixture.scratch.path().join("hide-list"), "").unwrap();
    let output = fixture.publish(&["--apply"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("gh secret list"),
        "{}",
        stderr(&output)
    );
    assert!(!fixture.marker().exists());
}

/// Private repositories do not receive the organization secret, so the targets list them
/// under `compressed` for a repository secret of their own.
fn compressed_targets(repositories: &[&str]) -> String {
    let list: Vec<String> = repositories.iter().map(|r| format!("\"{r}\"")).collect();
    format!(
        r#"{{"organization": "example", "plain": true, "sliced": ["{SLICED}"], "compressed": [{}]}}"#,
        list.join(", ")
    )
}

#[test]
fn compressed_targets_parse_and_default() {
    let listed =
        b10x_gates::publish::Targets::parse(compressed_targets(&[OTHER, SLICED]).as_bytes())
            .unwrap();
    assert_eq!(
        listed.compressed,
        vec![OTHER.to_string(), SLICED.to_string()]
    );
    // A targets file written before the field existed still parses, with no repository
    // getting a compressed secret.
    let older = b10x_gates::publish::Targets::parse(
        format!(r#"{{"organization": "example", "plain": true, "sliced": ["{SLICED}"]}}"#)
            .as_bytes(),
    )
    .unwrap();
    assert!(older.compressed.is_empty());
    assert_eq!(older.sliced, vec![SLICED.to_string()]);
    let empty = b10x_gates::publish::Targets::parse(b"{}").unwrap();
    assert!(empty.compressed.is_empty());
    let fixture = Fixture::new();
    let output = fixture.publish(&["--apply"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        !fixture.calls().iter().any(|(args, value)| value.is_some()
            && args.get(2).map(String::as_str) == Some("B10X_GATES_POLICY_GZ")
            && args.iter().any(|a| a == "--repo")),
        "a targets file without `compressed` wrote a repository compressed secret"
    );
}

#[test]
fn compressed_repositories_planned() {
    let fixture = Fixture::new();
    fixture.targets(&compressed_targets(&[OTHER, SLICED]));
    let output = fixture.publish(&[]);
    assert!(output.status.success(), "{}", stderr(&output));
    let out = stdout(&output);
    for repository in [OTHER, SLICED] {
        assert!(
            out.lines().any(|l| l.starts_with(&format!(
                "repository {repository} secret B10X_GATES_POLICY_GZ: "
            )) && l.ends_with(" bytes")),
            "{out}"
        );
    }
    assert!(out.contains("dry run"), "{out}");
    assert_eq!(fixture.sets(), 0, "a dry run wrote a secret");
    assert!(!fixture.marker().exists(), "a dry run moved the marker");
}

#[test]
fn compressed_repositories_published_and_read_back() {
    let fixture = Fixture::new();
    fixture.targets(&compressed_targets(&[OTHER, SLICED]));
    let output = fixture.publish(&["--apply"]);
    assert!(output.status.success(), "{}", stderr(&output));
    let committed = serde_json::to_value(
        Policy::parse(&fs::read(fixture.origin().join("policy.json")).unwrap()).unwrap(),
    )
    .unwrap();
    let organization = fixture.written("B10X_GATES_POLICY_GZ", &["--org", "example"]);
    for repository in [OTHER, SLICED] {
        let value = fixture.written("B10X_GATES_POLICY_GZ", &["--repo", repository]);
        // The whole policy, not a slice, in the encoding `ci` reads.
        assert_eq!(serde_json::to_value(gunzip(&value)).unwrap(), committed);
        assert_eq!(value, organization);
        let set = fixture
            .calls()
            .into_iter()
            .find(|(args, value)| {
                value.is_some()
                    && args.get(2).map(String::as_str) == Some("B10X_GATES_POLICY_GZ")
                    && args.iter().any(|a| a == repository)
            })
            .unwrap()
            .0;
        assert!(
            !set.iter().any(|a| a == "--visibility"),
            "a repository secret has no visibility: {set:?}"
        );
        assert!(
            fixture
                .calls()
                .iter()
                .any(|(args, _)| args[..2] == ["secret", "list"]
                    && args.iter().any(|a| a == "--repo")
                    && args.iter().any(|a| a == repository)),
            "{repository} was not read back"
        );
        assert!(
            stdout(&output).contains(&format!(
                "read back repository {repository} secret B10X_GATES_POLICY_GZ"
            )),
            "{}",
            stdout(&output)
        );
    }
    // The organization secret, the two plain slices and the two repository copies.
    assert_eq!(fixture.sets(), 5);
    let commit = git(fixture.origin(), &["rev-parse", "HEAD"]);
    assert_eq!(fs::read_to_string(fixture.marker()).unwrap().trim(), commit);
}

#[test]
fn compressed_repository_not_read_back_keeps_the_marker() {
    let fixture = Fixture::new();
    fixture.targets(&compressed_targets(&[OTHER]));
    fs::write(fixture.scratch.path().join("hide-scope"), OTHER).unwrap();
    let output = fixture.publish(&["--apply"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("gh secret list"), "{err}");
    assert!(err.contains(OTHER), "{err}");
    assert!(!fixture.marker().exists());
}

#[test]
fn compressed_repository_unenrolled_refused() {
    let fixture = Fixture::new();
    fixture.targets(&compressed_targets(&[OTHER, "example/unenrolled"]));
    let output = fixture.publish(&["--apply"]);
    assert!(!output.status.success());
    let err = stderr(&output);
    assert!(err.contains("example/unenrolled"), "{err}");
    assert!(err.contains("does not enrol"), "{err}");
    assert_eq!(fixture.sets(), 0);
    assert!(!fixture.marker().exists());
}

#[test]
fn compressed_repository_duplicate_refused() {
    let fixture = Fixture::new();
    fixture.targets(&compressed_targets(&[OTHER, OTHER]));
    let output = fixture.publish(&["--apply"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("more than once"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fixture.sets(), 0);
}

#[test]
fn compressed_repository_invalid_refused() {
    for invalid in [
        "example",
        "example/../other",
        "--org",
        "example/other/extra",
    ] {
        let fixture = Fixture::new();
        fixture.targets(&compressed_targets(&[invalid]));
        let output = fixture.publish(&["--apply"]);
        assert!(!output.status.success(), "{invalid} was accepted");
        assert!(
            stderr(&output).contains("invalid repository"),
            "{invalid}: {}",
            stderr(&output)
        );
        assert_eq!(fixture.sets(), 0, "{invalid}");
    }
}

/// A repository name gh could read as an option (a leading `-`) is refused as invalid
/// even when the policy enrols it, so nothing is published and no such argument reaches gh.
#[test]
fn compressed_repository_flag_like_name_refused() {
    let flag_like = "-R/other";
    let mut committed = policy(NONCE, 0);
    committed.repositories.insert(
        flag_like.into(),
        Repository {
            id: "123".into(),
            baseline: "0".repeat(40),
        },
    );
    let fixture = Fixture::with(&committed);
    fixture.targets(&compressed_targets(&[flag_like]));
    let output = fixture.publish(&["--apply"]);
    assert!(
        !output.status.success(),
        "{flag_like} was published to: {:?}",
        fixture
            .calls()
            .into_iter()
            .map(|(args, _)| args)
            .collect::<Vec<_>>()
    );
    assert!(
        stderr(&output).contains("invalid repository"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fixture.sets(), 0);
}
