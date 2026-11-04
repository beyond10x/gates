//! A policy exception reaches `personal-paths` like every other rule; an allowance
//! never does. An exception is bound to the exact repository, rule, location, line
//! content digest and line, so it admits one historical line and nothing beside it.
//! Every home path here is built at run time, so this source carries none.
use b10x_gates::{
    digest,
    git::Unit,
    policy::{Exception, Policy, Repository},
    scan::{self, SecretFinding, SecretScanner},
};
use std::collections::BTreeMap;

const REPOSITORY: &str = "example/repository";
const LOCATION: &str = "file:notes.md";

struct NoSecrets;
impl SecretScanner for NoSecrets {
    fn scan(&mut self, _: &[Unit]) -> anyhow::Result<Vec<SecretFinding>> {
        Ok(vec![])
    }
}

fn home() -> String {
    ["", "home", "fixture-person"].join("/")
}

fn historical_line() -> String {
    format!("the build ran in {}/work", home())
}

fn policy(exceptions: Vec<Exception>, allow_patterns: Vec<String>) -> Policy {
    Policy {
        version: if allow_patterns.is_empty() { 1 } else { 2 },
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: vec![],
        allow_patterns,
        repositories: BTreeMap::from([(
            REPOSITORY.into(),
            Repository {
                id: "123".into(),
                baseline: "0".repeat(40),
            },
        )]),
        signers: BTreeMap::new(),
        exceptions,
    }
}

fn exception(location: &str, content: &str, line: usize) -> Exception {
    Exception {
        repository: REPOSITORY.into(),
        rule: "personal-paths".into(),
        location: location.into(),
        content_sha256: digest(content.as_bytes()),
        line,
    }
}

/// `(line, rule)` of every finding in a one-unit candidate at `LOCATION`.
fn findings(policy: &Policy, text: &str) -> Vec<(usize, String)> {
    let unit = Unit {
        location: LOCATION.into(),
        bytes: text.as_bytes().to_vec(),
        workflow: false,
        inherited: None,
    };
    scan::run(policy, REPOSITORY, &[unit], &mut NoSecrets)
        .unwrap()
        .findings
        .into_iter()
        .map(|f| (f.line, f.rule))
        .collect()
}

fn text() -> String {
    format!("# Notes\n{}\n", historical_line())
}

#[test]
fn without_an_exception_the_historical_path_is_refused() {
    assert_eq!(
        findings(&policy(vec![], vec![]), &text()),
        vec![(2, "personal-paths".to_string())]
    );
}

#[test]
fn an_exact_exception_admits_the_historical_path() {
    let policy = policy(vec![exception(LOCATION, &historical_line(), 2)], vec![]);
    assert_eq!(findings(&policy, &text()), vec![]);
}

#[test]
fn the_exception_admits_no_other_content_line_or_location() {
    let other_content = format!("# Notes\n{}/other\n", home());
    let moved = format!("# Notes\n\n{}\n", historical_line());
    let policy_here = policy(vec![exception(LOCATION, &historical_line(), 2)], vec![]);
    assert_eq!(
        findings(&policy_here, &other_content),
        vec![(2, "personal-paths".to_string())],
        "another line content at the excepted line is refused"
    );
    assert_eq!(
        findings(&policy_here, &moved),
        vec![(3, "personal-paths".to_string())],
        "the excepted content on another line is refused"
    );
    let policy_elsewhere = policy(
        vec![exception("file:other.md", &historical_line(), 2)],
        vec![],
    );
    assert_eq!(
        findings(&policy_elsewhere, &text()),
        vec![(2, "personal-paths".to_string())],
        "an exception for another location admits nothing here"
    );
}

#[test]
fn an_allowance_never_admits_a_personal_path() {
    let allowance = format!("(?P<admit>{}/work)", home());
    assert_eq!(
        findings(&policy(vec![], vec![allowance]), &text()),
        vec![(2, "personal-paths".to_string())]
    );
}
