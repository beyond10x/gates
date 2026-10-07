//! Adversary cases for `story:hex-path-components`: hex-encoded path components
//! under a JSON `"components"` key. Every path and every hex component is built at
//! run time from its segments, so this source carries neither a home path nor its
//! encoding.
use b10x_gates::{
    git::Unit,
    policy::{Policy, Repository},
    scan::{self, SecretFinding, SecretScanner},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};

const REPOSITORY: &str = "example/repository";

struct NoSecrets;
impl SecretScanner for NoSecrets {
    fn scan(&mut self, _: &[Unit]) -> anyhow::Result<Vec<SecretFinding>> {
        Ok(vec![])
    }
}

fn policy() -> Policy {
    Policy {
        version: 1,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::from([(
            REPOSITORY.into(),
            Repository {
                id: "123".into(),
                baseline: "0".repeat(40),
            },
        )]),
        signers: BTreeMap::new(),
        exceptions: vec![],
    }
}

fn unit(bytes: impl AsRef<[u8]>) -> Unit {
    Unit {
        location: "file:sample".into(),
        bytes: bytes.as_ref().into(),
        workflow: false,
        inherited: None,
    }
}

/// ESS `NativePath`: the hex of every segment, no leading `/`, no marker for
/// whether the path is absolute or relative to the output root.
fn native(segments: &[&str]) -> Value {
    json!({
        "components": segments.iter().map(hex::encode).collect::<Vec<_>>(),
        "encoding": "UnixBytes1",
    })
}

/// The lines `personal-paths` was reported on.
fn personal_lines(policy: &Policy, text: &str) -> Vec<usize> {
    scan::run(policy, REPOSITORY, &[unit(text)], &mut NoSecrets)
        .unwrap()
        .findings
        .iter()
        .filter(|v| v.rule == "personal-paths")
        .map(|v| v.line)
        .collect()
}

/// A one-line ESS `state.json` whose root is a non-personal absolute directory and
/// whose ledger records one output file at the given output-root-relative path.
fn state_with_ledger_file(relative: &[&str]) -> String {
    let record = json!({
        "checksum": "0".repeat(64),
        "payload": {
            "root": native(&["srv", "build", "out"]),
            "checkpoint": {
                "phase": "Idle",
                "ledger": {
                    "owners": [{
                        "key": {"family": "projection:docs", "location": native(&[])},
                        "files": [{"path": native(relative), "data": {"length": 1, "mode": 420}}],
                    }],
                    "directories": [],
                },
            },
        },
    });
    format!("{}\n", serde_json::to_string(&record).unwrap())
}

/// Every ledger and transaction path in an ESS state record is relative to the
/// output root and uses the same `NativePath` shape as the absolute root, with no
/// marker saying which it is. The decoder joins every array with a leading `/`, so
/// an output tree with a top-level `home/` or `Users/` directory reads as a home
/// path. That is the fail-closed contract of `story:hex-path-components`: the
/// plain relative text stays admitted, the encoded array is refused on purpose.
#[test]
fn adv_relative_array_starting_with_home_is_refused_fail_closed() {
    let p = policy();
    for relative in [
        &["home", "guide", "intro.md"][..],
        &["Users", "models", "user.ts"][..],
        &["home", "LICENSE"][..],
    ] {
        let plain = format!("{}\n", relative.join("/"));
        assert!(
            personal_lines(&p, &plain).is_empty(),
            "control: the plain relative path is refused: {plain:?}"
        );
        let record = state_with_ledger_file(relative);
        assert_eq!(
            personal_lines(&p, &record),
            vec![1],
            "story:hex-path-components refuses the encoded array {:?} on purpose: the \
             decoder cannot tell a relative array from an absolute one, so it fails closed",
            relative.join("/")
        );
    }
}

/// Wall time of one scan of `text`, and the number of `personal-paths` findings.
fn timed(policy: &Policy, text: &str) -> (Duration, usize) {
    let u = unit(text);
    let start = Instant::now();
    let report = scan::run(policy, REPOSITORY, &[u], &mut NoSecrets).unwrap();
    (start.elapsed(), report.results["personal-paths"].findings)
}

/// A JSONL file of records each carrying a home root. The decoded pass checks
/// every span against `paths: Vec<usize>`, which grows by one per decoded finding,
/// so `n` arrays cost `n^2 / 2` comparisons. Two linear controls: the plain-text
/// line pass on the same number of findings, and the same number of decoded
/// arrays that are not personal (regex, decode and match, but no finding and no
/// `paths` lookup).
#[test]
fn adv_decoded_pass_scales_linearly_with_the_number_of_arrays() {
    let p = policy();
    let root = ["home", "fixture-person", "work"];
    let line = |segments: &[&str]| {
        format!(
            "{}\n",
            serde_json::to_string(&json!({"root": native(segments)})).unwrap()
        )
    };
    let personal = line(&root);
    let neutral = line(&["srv", "fixture-person", "work"]);
    let plain = format!("{}\n", ["", root[0], root[1], root[2]].join("/"));
    let (small, large) = (10_000, 80_000);
    let ratio = |a: Duration, b: Duration| b.as_secs_f64() / a.as_secs_f64().max(1e-9);
    // Load from other processes only ever inflates a measurement, so each side
    // keeps its fastest run: five of the small input, three of the large. Timing
    // the large input once let a loaded machine fail a linear pass.
    let scale = |text: &str, findings: bool| {
        let a = (0..5)
            .map(|_| {
                let (a, n) = timed(&p, &text.repeat(small));
                assert_eq!(n, if findings { small } else { 0 });
                a
            })
            .min()
            .unwrap();
        let b = (0..3)
            .map(|_| {
                let (b, n) = timed(&p, &text.repeat(large));
                assert_eq!(n, if findings { large } else { 0 });
                b
            })
            .min()
            .unwrap();
        (a, b, ratio(a, b))
    };
    let plain = scale(&plain, true);
    let neutral = scale(&neutral, false);
    let personal = scale(&personal, true);
    let report = format!(
        "{large}/{small} = 8x the input: plain line pass {:?} -> {:?} ({:.1}x); \
         non-personal arrays {:?} -> {:?} ({:.1}x); personal arrays {:?} -> {:?} ({:.1}x)",
        plain.0,
        plain.1,
        plain.2,
        neutral.0,
        neutral.1,
        neutral.2,
        personal.0,
        personal.1,
        personal.2,
    );
    eprintln!("{report}");
    assert!(personal.2 < 16.0, "superlinear decoded pass: {report}");
}

/// Spellings of the same absolute root the decoder must still read.
#[test]
fn adv_hex_root_spellings_are_refused() {
    let p = policy();
    let parts = ["home", "fixture-person", "work"];
    let lower: Vec<String> = parts.iter().map(hex::encode).collect();
    let upper: Vec<String> = parts.iter().map(hex::encode_upper).collect();
    let list = |items: &[String], sep: &str| {
        items
            .iter()
            .map(|v| format!("\"{v}\""))
            .collect::<Vec<_>>()
            .join(sep)
    };
    let compact = format!("{{\"components\":[{}]}}", list(&lower, ","));
    let pretty = serde_json::to_string_pretty(&native(&parts)).unwrap();
    let escape = |v: &str| serde_json::to_string(&Value::String(v.to_owned())).unwrap();
    // An odd-length element contributes its own text (contract), here a name
    // spelled in hex digits.
    let odd = format!(
        "{{\"components\":[\"{}\",\"abe\",\"{}\"]}}",
        lower[0], lower[2]
    );
    let cases: Vec<(String, usize)> = vec![
        // Uppercase digits, the marker first.
        (
            format!(
                "{{\"encoding\":\"UnixBytes1\",\"components\":[{}]}}\n",
                list(&upper, ",")
            ),
            1,
        ),
        // CRLF, tabs, the key, the colon and the bracket on separate lines.
        (
            format!(
                "{{\r\n\t\"components\"\r\n\t:\r\n\t[\r\n\t\t{}\r\n\t]\r\n}}\r\n",
                list(&lower, ",\r\n\t\t")
            ),
            2,
        ),
        // Marker renamed.
        (
            format!(
                "{{\"components\":[{}],\"kind\":\"Other\"}}\n",
                list(&lower, ",")
            ),
            1,
        ),
        // Pasted into a JSON string, then that string pasted into another.
        (format!("{}\n", escape(&escape(&compact))), 1),
        (format!("{}\n", escape(&escape(&pretty))), 1),
        // Not on the first line.
        (format!("prefix\n\nsuffix {compact}\n"), 3),
        (format!("{odd}\n"), 1),
        // A plain path and the array on one line: one finding, not two.
        (
            format!("{} {compact}\n", ["", parts[0], parts[1], ""].join("/")),
            1,
        ),
    ];
    for (text, line) in cases {
        assert_eq!(personal_lines(&p, &text), vec![line], "missed: {text:?}");
    }
}

/// `"components"` keys that are not an encoded home path.
#[test]
fn adv_unrelated_components_keys_are_admitted() {
    let p = policy();
    let digest = |v: &[u8]| b10x_gates::digest(v);
    let cases = [
        json!({"openapi": "3.1.0", "components": {"schemas": {"User": {"type": "object"}}}}),
        // Names that happen to be hex digits, even and odd length.
        json!({"components": ["face", "bead", "cafe", "decade", "abe", ""]}),
        json!({"components": [digest(b"one"), digest(b"two")]}),
        json!({"components": []}),
        // The parent of every home directory names nobody.
        native(&["home"]),
        native(&["Users"]),
    ];
    for value in cases {
        for text in [
            format!("{}\n", serde_json::to_string(&value).unwrap()),
            format!("{}\n", serde_json::to_string_pretty(&value).unwrap()),
        ] {
            assert!(
                personal_lines(&p, &text).is_empty(),
                "false refusal: {text}"
            );
        }
    }
}
