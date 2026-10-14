//! Adversarial cases for `gates.delivery.LoadCiPolicy` (`ess/domains/delivery.yaml`):
//! `B10X_GATES_POLICY_GZ` is refused naming the variable whenever it is given and does
//! not decode, decompress within 4 MiB or parse; it never falls back to another source,
//! and no diagnostic carries a byte of the value.
use b10x_gates::policy::{self, CiPolicySource, Policy};
use base64::Engine;
use flate2::{Compression, write::GzEncoder};
use std::{
    collections::BTreeMap, ffi::OsStr, io::Write, os::unix::ffi::OsStrExt, process::Command,
};

const VARIABLE: &str = "B10X_GATES_POLICY_GZ";
const BOUND: usize = 4 << 20;

fn marker() -> String {
    // Built at run time so the source carries no literal the scanner would hold.
    ["zq", "marker", "value", "x7"].join("-")
}

fn policy_with(literal: &str) -> Policy {
    Policy {
        version: 2,
        nonce: "synthetic-policy-nonce-for-adversary-1234".into(),
        forbidden_literals: vec![literal.into()],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::new(),
        signers: BTreeMap::new(),
        exceptions: vec![],
    }
}

fn policy_json() -> String {
    serde_json::to_string(&policy_with(&["synthetic", "rule", "term"].join("-"))).unwrap()
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The refusal for a compressed value given beside a valid JSON policy: refused, naming
/// the variable, never the JSON fallback.
fn refused_without_fallback(compressed: &str) -> String {
    let json = policy_json();
    match policy::ci_policy(Some(compressed), Some(&json)) {
        Ok(Some((_, source))) => panic!("admitted from {source:?}"),
        Ok(None) => panic!("fell back to the protected file"),
        Err(error) => {
            let error = format!("{error:#}");
            assert!(error.contains(VARIABLE), "{error}");
            error
        }
    }
}

// --- gzip framing -------------------------------------------------------------------

#[test]
fn trailing_garbage_after_the_gzip_member_is_refused() {
    // `gzip -t` reports "trailing garbage"; the value is not what the operator encoded.
    let mut bytes = gzip(policy_json().as_bytes());
    bytes.extend_from_slice(b"\x00\x01trailing bytes that are not a gzip member");
    refused_without_fallback(&encode(&bytes));
}

#[test]
fn a_second_gzip_member_is_not_silently_dropped() {
    // `gzip -dc` decodes every member and concatenates them; a loader that reads only the
    // first loads a policy other than the one `gzip -dc` shows.
    let mut bytes = gzip(policy_json().as_bytes());
    bytes.extend_from_slice(&gzip(b"{\"second\": \"member\"}"));
    refused_without_fallback(&encode(&bytes));
}

#[test]
fn two_concatenated_encodings_are_not_silently_half_read() {
    // Two values pasted one after the other: whitespace is ignored, so when the first
    // encoding needs no padding the pair decodes to two gzip members.
    let mut json = policy_json();
    let mut first = gzip(json.as_bytes());
    while !first.len().is_multiple_of(3) {
        json.push(' ');
        first = gzip(json.as_bytes());
    }
    let second = gzip(policy_json().replace("rule", "rulf").as_bytes());
    let pasted = format!("{}\n{}", encode(&first), encode(&second));
    refused_without_fallback(&pasted);
}

#[test]
fn truncated_trailer_is_refused() {
    let bytes = gzip(policy_json().as_bytes());
    refused_without_fallback(&encode(&bytes[..bytes.len() - 4]));
    refused_without_fallback(&encode(&bytes[..bytes.len() - 8]));
}

#[test]
fn truncated_deflate_stream_is_refused() {
    let bytes = gzip(policy_json().as_bytes());
    refused_without_fallback(&encode(&bytes[..bytes.len() / 2]));
    refused_without_fallback(&encode(&bytes[..10]));
}

#[test]
fn corrupted_crc_is_refused() {
    let mut bytes = gzip(policy_json().as_bytes());
    let at = bytes.len() - 8;
    bytes[at] ^= 0xff;
    refused_without_fallback(&encode(&bytes));
}

// --- base64 alphabet ----------------------------------------------------------------

#[test]
fn url_safe_alphabet_is_refused() {
    // Find an encoding that uses `+` or `/`, then switch it to the URL-safe alphabet.
    let mut json = policy_json();
    let encoded = loop {
        let e = encode(&gzip(json.as_bytes()));
        if e.contains('+') || e.contains('/') {
            break e;
        }
        json.push(' ');
    };
    refused_without_fallback(&encoded.replace('+', "-").replace('/', "_"));
}

#[test]
fn missing_padding_is_refused() {
    let mut json = policy_json();
    let encoded = loop {
        let e = encode(&gzip(json.as_bytes()));
        if e.ends_with('=') {
            break e;
        }
        json.push(' ');
    };
    refused_without_fallback(encoded.trim_end_matches('='));
}

#[test]
fn whitespace_only_is_given_and_refused() {
    // Set and non-empty: a whitespace-only value is a given (broken) value, not absence.
    for value in [" ", "\n", "\r\n", "\t \n"] {
        refused_without_fallback(value);
    }
}

#[test]
fn non_ascii_whitespace_is_not_ignored() {
    let encoded = encode(&gzip(policy_json().as_bytes()));
    refused_without_fallback(&format!("{encoded}\u{a0}"));
}

// --- the 4 MiB bound -----------------------------------------------------------------

fn padded_to(length: usize) -> Vec<u8> {
    let mut json = policy_json().into_bytes();
    assert!(json.len() < length);
    json.resize(length, b' ');
    json
}

#[test]
fn exactly_the_bound_is_admitted() {
    let value = encode(&gzip(&padded_to(BOUND)));
    let (_, source) = policy::ci_policy(Some(&value), None).unwrap().unwrap();
    assert_eq!(source, CiPolicySource::Compressed);
}

#[test]
fn one_byte_over_the_bound_is_refused_by_the_bound() {
    // A valid policy padded past the bound with JSON whitespace: only the bound can refuse
    // it. The existing over-bound case uses 5 MiB of spaces, which the parser refuses
    // anyway, so it stays green when the bound is removed.
    let value = encode(&gzip(&padded_to(BOUND + 1)));
    let error = format!(
        "{:#}",
        policy::ci_policy(Some(&value), None)
            .err()
            .expect("a policy over the bound was admitted")
    );
    assert!(error.contains(VARIABLE), "{error}");
    assert!(error.contains("decompresses to more than"), "{error}");
}

#[test]
fn only_the_bound_separates_these_inputs_from_admission() {
    // The mutant "drop the take/ensure bound" expressed without editing the code: the
    // input of `ci_policy.rs::compressed_over_the_bound_names_the_variable` (5 MiB of
    // spaces) is refused by the parser alone, so that case survives the mutant; the input
    // of `one_byte_over_the_bound_is_refused_by_the_bound` parses, so only the bound
    // refuses it.
    assert!(Policy::parse(&vec![b' '; 5 << 20]).is_err());
    assert!(Policy::parse(&padded_to(BOUND + 1)).is_ok());
}

#[test]
fn the_bound_counts_every_member() {
    // Two members each under the bound, together over it.
    let half = padded_to(BOUND / 2 + 16);
    let mut bytes = gzip(&half);
    bytes.extend_from_slice(&gzip(&vec![b' '; BOUND / 2 + 16]));
    refused_without_fallback(&encode(&bytes));
}

// --- no byte of the value in diagnostics ------------------------------------------------

fn assert_no_value_bytes(error: &str, secret: &str) {
    assert!(!error.contains(secret), "{error}");
}

#[test]
fn refusals_carry_no_byte_of_the_value() {
    let secret = marker();
    let cases: Vec<String> = vec![
        // not base64, the marker itself
        secret.clone(),
        // base64 of non-gzip bytes carrying the marker
        encode(secret.as_bytes()),
        // gzip of JSON that is not a policy, carrying the marker as a field name and value
        encode(&gzip(format!("{{\"{secret}\": \"{secret}\"}}").as_bytes())),
        // a policy whose private rule does not compile and holds the marker
        encode(&gzip(
            serde_json::to_string(&Policy {
                forbidden_patterns: vec![format!("({secret}")],
                ..policy_with(&secret)
            })
            .unwrap()
            .as_bytes(),
        )),
        // a policy whose literal is too short, beside the marker
        encode(&gzip(
            serde_json::to_string(&Policy {
                forbidden_literals: vec![secret.clone(), "ab".into()],
                ..policy_with(&secret)
            })
            .unwrap()
            .as_bytes(),
        )),
    ];
    for value in cases {
        let error = refused_without_fallback(&value);
        assert_no_value_bytes(&error, &secret);
        let error = format!("{:?}", policy::ci_policy(Some(&value), None).err().unwrap());
        assert_no_value_bytes(&error, &secret);
    }
}

fn run_ci(env: &[(&str, &OsStr)], home: &std::path::Path) -> (bool, String, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_b10x-gates"));
    command
        .args(["ci", "--event", "/nonexistent/event.json", "--objects"])
        .arg(home)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home)
        .env("TMPDIR", home)
        .env("XDG_CONFIG_HOME", home);
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("adversary-ci-policy-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

#[test]
fn ci_output_carries_no_byte_of_a_refused_value() {
    let secret = marker();
    let home = scratch();
    let value = encode(&gzip(
        serde_json::to_string(&Policy {
            forbidden_patterns: vec![format!("({secret}")],
            ..policy_with(&secret)
        })
        .unwrap()
        .as_bytes(),
    ));
    let (ok, stdout, stderr) = run_ci(&[(VARIABLE, OsStr::new(&value))], home.path());
    assert!(!ok);
    assert!(stderr.contains(VARIABLE), "{stderr}");
    assert!(
        !stderr.contains(&secret) && !stdout.contains(&secret),
        "{stderr}"
    );
    assert!(!stderr.contains(&value), "{stderr}");
}

#[test]
fn ci_refuses_non_utf8_compressed_value_without_fallback() {
    let home = scratch();
    let json = policy_json();
    let (ok, _, stderr) = run_ci(
        &[
            (VARIABLE, OsStr::from_bytes(b"H4sI\xff\xfe")),
            ("B10X_GATES_POLICY_JSON", OsStr::new(&json)),
        ],
        home.path(),
    );
    assert!(!ok);
    assert!(stderr.contains(VARIABLE), "{stderr}");
    assert!(!stderr.contains("\u{fffd}"), "{stderr}");
}

#[test]
fn ci_refuses_whitespace_only_compressed_value_without_fallback() {
    let home = scratch();
    let json = policy_json();
    let (ok, _, stderr) = run_ci(
        &[
            (VARIABLE, OsStr::new("\n")),
            ("B10X_GATES_POLICY_JSON", OsStr::new(&json)),
        ],
        home.path(),
    );
    assert!(!ok);
    assert!(stderr.contains(VARIABLE), "{stderr}");
}

#[test]
fn ci_does_not_fall_back_to_the_file_when_the_json_variable_is_set_but_not_unicode() {
    // The JSON variable is set, so it is the source; a value that is not Unicode is a
    // given broken value. `std::env::var(..).ok()` turns it into absence, and `ci` then
    // reads the protected file instead.
    use std::os::unix::fs::PermissionsExt;
    let home = scratch();
    let dir = home.path().join("b10x/gates");
    std::fs::create_dir_all(&dir).unwrap();
    for d in [home.path().join("b10x"), dir.clone()] {
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let file = dir.join("policy.json");
    std::fs::write(&file, policy_json()).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let (ok, _, stderr) = run_ci(
        &[(
            "B10X_GATES_POLICY_JSON",
            OsStr::from_bytes(b"{\"version\": \xff}"),
        )],
        home.path(),
    );
    assert!(!ok);
    assert!(
        stderr.contains("B10X_GATES_POLICY_JSON") || stderr.contains("policy format invalid"),
        "the protected file was read instead of the set JSON variable: {stderr}"
    );
}
