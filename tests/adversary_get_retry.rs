//! Adversary cases for the GET retry on a request that gets no answer. A plain-HTTP loopback
//! server answers as GitHub through `Github::for_loopback_test`.
use b10x_gates::delivery::Github;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

const TOKEN: &str = "synthetic-token";
const LIST: &str =
    "/repos/example/repository/commits/0000000000000000000000000000000000000000/pulls";

/// Reads the request line and headers; returns the method.
fn read_head(stream: &mut std::net::TcpStream) -> Option<String> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let method = line.split_whitespace().next()?.to_owned();
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        if header.trim_end().is_empty() {
            return Some(method);
        }
    }
}

/// A loopback server whose first `cut` answers are a 200 whose body stops after its first
/// bytes, the connection then closed; every later answer is the full body.
fn cutting_server(cut: usize, full: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let Some(method) = read_head(&mut stream) else {
                continue;
            };
            let index = {
                let mut log = log.lock().unwrap();
                log.push(method);
                log.len() - 1
            };
            let sent = if index < cut { &full[..2] } else { full };
            let _ = stream.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{sent}",
                    full.len()
                )
                .as_bytes(),
            );
            let _ = stream.flush();
            drop(stream);
        }
    });
    (port, seen)
}

/// The connection closes in the middle of a 200's body: GitHub's answer never arrived whole.
/// The change says a GET whose connection closes before the answer is sent again; one whose
/// answer is cut off must be sent again too, or refused. It must not come back as a success
/// holding `null` in place of the list GitHub sent.
#[test]
fn a_get_whose_answer_is_cut_off_is_sent_again_or_refused() {
    let (port, seen) = cutting_server(1, r#"[{"number":1,"merge_commit_sha":null}]"#);
    let github = Github::for_loopback_test(TOKEN.into(), port).unwrap();
    let result = github.api_response(Method::GET, LIST, None);
    let sends = seen.lock().unwrap().len();
    match result {
        Err(_) => {}
        Ok((status, value)) => assert_eq!(
            (status, value, sends),
            (
                StatusCode::OK,
                json!([{"number": 1, "merge_commit_sha": Value::Null}]),
                2
            ),
            "a cut-off 200 was admitted as a success after {sends} send(s)"
        ),
    }
}

/// Every answer is cut off: the GET is sent `GET_ATTEMPTS` (5) times and ends in an error that
/// names the failure's kind alone, never a success holding `null`.
#[test]
fn a_get_whose_answer_is_cut_off_every_time_is_an_error_after_five_sends() {
    let (port, seen) = cutting_server(usize::MAX, r#"[{"number":1}]"#);
    let github = Github::for_loopback_test(TOKEN.into(), port).unwrap();
    let result = github.api_response(Method::GET, LIST, None);
    let sends = seen.lock().unwrap().len();
    let error = match result {
        Ok(answer) => panic!("a cut-off 200 was admitted as {answer:?} after {sends} send(s)"),
        Err(error) => format!("{error:#}"),
    };
    assert_eq!(sends, 5, "{error}");
    assert_eq!(
        error,
        "GitHub request failed (other); sensitive response withheld"
    );
}

/// A write whose answer is cut off may still have happened: it is sent once, never again, and
/// its unreadable body is the same as an empty one, as before.
#[test]
fn a_write_whose_answer_is_cut_off_is_sent_once() {
    let (port, seen) = cutting_server(usize::MAX, r#"{"number":1}"#);
    let github = Github::for_loopback_test(TOKEN.into(), port).unwrap();
    let result = github.api_response(Method::PATCH, "/repos/example/repository/pulls/1", None);
    let sends = seen.lock().unwrap().clone();
    assert_eq!(sends, ["PATCH"]);
    assert_eq!(result.unwrap(), (StatusCode::OK, Value::Null));
}
