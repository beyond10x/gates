//! Adversary cases for `story:token-env-error-value`: a secret-bearing variable whose value
//! is valid Unicode but invalid in content (bad base64, bad gzip, a policy that does not
//! parse or validate, a token a header cannot carry, a token GitHub refuses) must not reach
//! any form of the refusal (`{}`, `{:#}`, `{:?}`) or any output of the binary. Each value
//! carries a distinctive run that a parser quoting its input would echo.
use b10x_gates::{
    delivery::Github,
    policy::{Policy, Repository},
};
use base64::Engine;
use std::{
    collections::BTreeMap,
    ffi::OsStr,
    io::{Read, Write},
    net::TcpListener,
    process::Command,
};

/// Built at run time so the source carries no credential-shaped literal.
fn run() -> String {
    [["gh", "p_"].concat().as_str(), "Zq7Lm4", "Rt9Kp2", "Wx4Vb6"].concat()
}

/// No four consecutive bytes of the run.
fn assert_no_part(text: &str) {
    let run = run();
    for part in run.as_bytes().windows(4) {
        let part = std::str::from_utf8(part).unwrap();
        assert!(!text.contains(part), "carries {part:?}: {text}");
    }
}

fn forms(error: &anyhow::Error) -> String {
    format!("{error}\n{error:#}\n{error:?}")
}

fn policy() -> Policy {
    Policy {
        version: 2,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::from([(
            "example/repository".into(),
            Repository {
                id: "123".into(),
                baseline: "0".repeat(40),
            },
        )]),
        signers: BTreeMap::new(),
        exceptions: vec![],
    }
}

fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// Policy texts that are invalid in content, each carrying the run.
fn bad_policies() -> Vec<String> {
    let run = run();
    let mut short_nonce = policy();
    short_nonce.nonce = run.clone();
    let mut bad_id = policy();
    bad_id.repositories = BTreeMap::from([(
        "example/repository".into(),
        Repository {
            id: run.clone(),
            baseline: "0".repeat(40),
        },
    )]);
    let mut bad_baseline = policy();
    bad_baseline.repositories = BTreeMap::from([(
        "example/repository".into(),
        Repository {
            id: "123".into(),
            baseline: run.clone(),
        },
    )]);
    let mut bad_pattern = policy();
    bad_pattern.forbidden_patterns = vec![format!("({run}")];
    vec![
        run.clone(),
        format!("{{\"version\":\"{run}\"}}"),
        format!("{{\"{run}\":1}}"),
        format!("[\"{run}\"]"),
        format!("{{\"version\":2,\"nonce\":\"{run}\"}}"),
        serde_json::to_string(&short_nonce).unwrap(),
        serde_json::to_string(&bad_id).unwrap(),
        serde_json::to_string(&bad_baseline).unwrap(),
        serde_json::to_string(&bad_pattern).unwrap(),
    ]
}

/// `b10x-gates ci` with exactly `env` set besides the basics; its whole output.
fn ci(env: &[(&str, &OsStr)]) -> String {
    let home = tempfile::Builder::new()
        .prefix("adversary-token-env-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_b10x-gates"));
    command
        .args(["ci", "--event", "/nonexistent/event.json", "--objects"])
        .arg(home.path().join("objects"))
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("HOME", home.path())
        .env("TMPDIR", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("GITHUB_TOKEN", "unused-workflow-token");
    for (key, value) in env {
        command.env(key, value);
    }
    let output = command.output().unwrap();
    assert!(!output.status.success(), "ci succeeded: {output:?}");
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn ci_refuses_a_compressed_policy_invalid_in_content_without_its_bytes() {
    let run = run();
    let valid = serde_json::to_vec(&policy()).unwrap();
    let mut trailing = gzip(&valid);
    trailing.extend_from_slice(run.as_bytes());
    let mut values = vec![
        format!("{run}!*"),
        format!("{}{run}", b64(b"x")),
        b64(run.as_bytes()),
        b64(&trailing),
        b64(&gzip(&valid)[..20]),
    ];
    values.extend(bad_policies().iter().map(|p| b64(&gzip(p.as_bytes()))));
    for value in values {
        let output = ci(&[("B10X_GATES_POLICY_GZ", OsStr::new(&value))]);
        assert!(output.contains("B10X_GATES_POLICY_GZ"), "{value}: {output}");
        assert_no_part(&output);
    }
}

#[test]
fn ci_refuses_a_json_policy_invalid_in_content_without_its_bytes() {
    for value in bad_policies() {
        let output = ci(&[("B10X_GATES_POLICY_JSON", OsStr::new(&value))]);
        assert!(
            !output.contains("event"),
            "policy admitted: {value}: {output}"
        );
        assert_no_part(&output);
    }
}

/// A token a header cannot carry: the request is never built, and no form of the refusal
/// carries the token.
#[test]
fn a_token_a_header_cannot_carry_is_refused_without_its_bytes() {
    let run = run();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    for token in [
        format!("{run}\nsecond"),
        format!("{run}\r\nX-Injected: 1"),
        format!("{run}\u{7f}"),
        format!("{run}\0"),
    ] {
        let error = Github::for_loopback_test(token, port)
            .and_then(|github| {
                github.api(
                    reqwest::Method::GET,
                    "/repos/example/repository/pulls/1",
                    None,
                )
            })
            .expect_err("a token with a control character admitted");
        assert_no_part(&forms(&error));
    }
}

/// A token GitHub refuses: the server answers 401 with GitHub's refusal and echoes the
/// `Authorization` header it received in a field GitHub never fills, so a refusal that
/// carried any of the body would carry the token.
#[test]
fn a_token_github_refuses_is_refused_without_its_bytes() {
    let run = run();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = stream.read(&mut buffer).unwrap();
                if n == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..n]);
            }
            let text = String::from_utf8_lossy(&request);
            let authorization = text
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("authorization:"))
                .unwrap_or_default()
                .to_owned();
            let body = serde_json::json!({
                "message": "Bad credentials",
                "documentation_url": authorization,
            })
            .to_string();
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        }
    });
    let error = Github::for_loopback_test(run, port)
        .unwrap()
        .api(
            reqwest::Method::GET,
            "/repos/example/repository/pulls/1",
            None,
        )
        .expect_err("a refused token admitted");
    let text = forms(&error);
    assert!(text.contains("401"), "{text}");
    assert_no_part(&text);
}
