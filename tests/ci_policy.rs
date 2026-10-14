//! `b10x-gates ci` reads the private policy from `B10X_GATES_POLICY_GZ` (gzip, then
//! standard base64) when it is set and non-empty, else from `B10X_GATES_POLICY_JSON`,
//! else from the protected file (modelled as `gates.delivery.LoadCiPolicy` in
//! `ess/domains/delivery.yaml`). Each test is named after the outcome it holds.
use b10x_gates::policy::{self, CiPolicySource, Policy};
use base64::Engine;
use flate2::{Compression, write::GzEncoder};
use std::{collections::BTreeMap, io::Write, process::Command};

fn policy_json() -> String {
    let policy = Policy {
        version: 2,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::new(),
        signers: BTreeMap::new(),
        exceptions: vec![],
    };
    serde_json::to_string_pretty(&policy).unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn digest(policy: &Policy) -> serde_json::Value {
    serde_json::to_value(policy).unwrap()
}

fn refusal(compressed: Option<&str>, json: Option<&str>) -> String {
    let error = policy::ci_policy(compressed, json)
        .err()
        .expect("the policy was admitted");
    format!("{error:#}")
}

#[test]
fn loaded_from_compressed() {
    let json = policy_json();
    let compressed = encode(&gzip(json.as_bytes()));
    let (policy, source) = policy::ci_policy(Some(&compressed), None).unwrap().unwrap();
    assert_eq!(source, CiPolicySource::Compressed);
    assert_eq!(
        digest(&policy),
        digest(&Policy::parse(json.as_bytes()).unwrap())
    );
}

#[test]
fn compressed_wins_over_json() {
    let compressed = encode(&gzip(policy_json().as_bytes()));
    let (_, source) = policy::ci_policy(Some(&compressed), Some("not a policy"))
        .unwrap()
        .unwrap();
    assert_eq!(source, CiPolicySource::Compressed);
}

#[test]
fn compressed_wrapped_lines_accepted() {
    // `base64` without `-w0` wraps at 76 columns; the line breaks are not data.
    let compressed = encode(&gzip(policy_json().as_bytes()));
    let wrapped: Vec<String> = compressed
        .as_bytes()
        .chunks(76)
        .map(|c| String::from_utf8(c.to_vec()).unwrap())
        .collect();
    let wrapped = format!("{}\n", wrapped.join("\n"));
    let (_, source) = policy::ci_policy(Some(&wrapped), None).unwrap().unwrap();
    assert_eq!(source, CiPolicySource::Compressed);
}

#[test]
fn compressed_undecodable_names_the_variable() {
    let error = refusal(Some("%%% not base64 %%%"), None);
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn compressed_not_gzip_names_the_variable() {
    let error = refusal(Some(&encode(policy_json().as_bytes())), None);
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn compressed_not_a_policy_names_the_variable() {
    let error = refusal(Some(&encode(&gzip(b"{\"version\": 2}"))), None);
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn compressed_over_the_bound_names_the_variable() {
    // A valid policy padded past the bound with JSON whitespace: only the bound refuses it.
    let padded = format!("{}{}", policy_json(), " ".repeat(5 << 20));
    let error = refusal(Some(&encode(&gzip(padded.as_bytes()))), None);
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn compressed_undecodable_never_falls_back() {
    // A valid JSON policy beside a broken compressed one is not used.
    let json = policy_json();
    let error = refusal(Some("garbage"), Some(&json));
    assert!(error.contains("B10X_GATES_POLICY_GZ"), "{error}");
}

#[test]
fn empty_compressed_reads_json() {
    let json = policy_json();
    let (_, source) = policy::ci_policy(Some(""), Some(&json)).unwrap().unwrap();
    assert_eq!(source, CiPolicySource::Json);
}

#[test]
fn json_path_unchanged() {
    let json = policy_json();
    let (policy, source) = policy::ci_policy(None, Some(&json)).unwrap().unwrap();
    assert_eq!(source, CiPolicySource::Json);
    assert_eq!(
        digest(&policy),
        digest(&Policy::parse(json.as_bytes()).unwrap())
    );
    // A set but empty JSON variable is still parsed, and refused, as before.
    assert_eq!(refusal(None, Some("")), "policy format invalid");
}

#[test]
fn neither_reads_the_file() {
    assert!(policy::ci_policy(None, None).unwrap().is_none());
    assert!(policy::ci_policy(Some(""), None).unwrap().is_none());
}

#[test]
fn ci_refuses_undecodable_compressed_policy() {
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .args(["ci", "--event", "/nonexistent/event.json", "--objects"])
        .arg(home.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("B10X_GATES_POLICY_GZ", "garbage")
        .env("B10X_GATES_POLICY_JSON", policy_json())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("B10X_GATES_POLICY_GZ"), "{stderr}");
}

#[test]
fn ci_reads_compressed_policy_before_the_event() {
    // A valid compressed policy beside a broken JSON one: `ci` gets past the policy and
    // stops at the missing event file.
    let home = tempfile::tempdir().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
        .args(["ci", "--event", "/nonexistent/event.json", "--objects"])
        .arg(home.path())
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env(
            "B10X_GATES_POLICY_GZ",
            encode(&gzip(policy_json().as_bytes())),
        )
        .env("B10X_GATES_POLICY_JSON", "not a policy")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("policy"), "{stderr}");
}
