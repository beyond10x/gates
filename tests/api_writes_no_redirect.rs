//! `story:api-writes-no-redirect`: the GitHub client sends a write once and never along a
//! redirect, follows a read's redirect only to an admitted path on the API host, and never
//! sends the authorization header anywhere else. A plain-HTTP loopback server answers as
//! GitHub through `Github::for_loopback_test`, the one constructor that takes a base.
use b10x_gates::delivery::Github;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

const TOKEN: &str = "synthetic-token";
const FIRST: &str = "/repos/example/repository/first";
const SECOND: &str = "/repos/example/repository/second";
/// Carried in every refused `Location`; a refusal that shows it shows the `Location`.
const MARKER: &str = "location-marker";
const WRITES: [Method; 4] = [Method::POST, Method::PUT, Method::PATCH, Method::DELETE];
/// 307 and 308 first: those are the ones reqwest re-sends a write along, body included.
const REDIRECTS: [u16; 5] = [307, 308, 301, 302, 303];

/// One request as the server read it.
#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

struct Answer {
    status: u16,
    location: Option<String>,
    body: String,
}

impl Answer {
    fn redirect(status: u16, location: impl Into<String>) -> Self {
        Self {
            status,
            location: Some(location.into()),
            body: String::new(),
        }
    }

    fn json(body: Value) -> Self {
        Self {
            status: 200,
            location: None,
            body: body.to_string(),
        }
    }
}

/// A loopback HTTP/1.1 server that records each request before it answers, one connection
/// at a time, so when the blocking client returns every request it sent is in `seen`.
struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn start(answer: impl Fn(&Seen, u16) -> Answer + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                log.lock().unwrap().push(request.clone());
                let reply = answer(&request, port);
                let mut head = format!("HTTP/1.1 {} Answer\r\n", reply.status);
                if let Some(location) = &reply.location {
                    head.push_str(&format!("Location: {location}\r\n"));
                }
                head.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    reply.body.len()
                ));
                let _ = stream.write_all(head.as_bytes());
                if request.method != "HEAD" {
                    let _ = stream.write_all(reply.body.as_bytes());
                }
                let _ = stream.flush();
            }
        });
        Self { port, seen }
    }

    fn seen(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn github(&self) -> Github {
        Github::for_loopback_test(TOKEN.into(), self.port).unwrap()
    }
}

fn read_request(stream: &mut std::net::TcpStream) -> Option<Seen> {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).ok()?;
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_owned();
    let target = parts.next()?.to_owned();
    let mut authorization = None;
    let mut length = 0;
    loop {
        let mut header = String::new();
        reader.read_line(&mut header).ok()?;
        let header = header.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':')?;
        match name.trim().to_ascii_lowercase().as_str() {
            "authorization" => authorization = Some(value.trim().to_owned()),
            "content-length" => length = value.trim().parse().ok()?,
            _ => {}
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    Some(Seen {
        method,
        target,
        authorization,
        body,
    })
}

/// A server that answers nothing but records: the "other host" (another port is another
/// origin, and reqwest itself treats it as another host).
fn other_host() -> Server {
    Server::start(|_, _| Answer::json(json!({"other": true})))
}

/// Refused writes and reads must not show the `Location`, which GitHub fills and which
/// may carry what the caller never wrote.
fn assert_location_withheld(text: &str) {
    assert!(!text.contains(MARKER), "the Location is shown: {text}");
    assert!(!text.contains("second"), "the Location is shown: {text}");
}

/// What is wrong with how one write answered with a redirect went, if anything.
fn write_failure(
    method: &Method,
    body: &Value,
    seen: &[Seen],
    result: anyhow::Result<(StatusCode, Value)>,
    status: u16,
) -> Option<String> {
    if seen
        .iter()
        .any(|r| r.target.starts_with(SECOND) && r.authorization.is_some())
    {
        return Some(format!(
            "a request to the second location carries the authorization: {seen:?}"
        ));
    }
    if seen.iter().any(|r| r.target != FIRST) {
        return Some(format!("sent to the redirect's location: {seen:?}"));
    }
    if seen.len() != 1 {
        return Some(format!("received {} times, not once", seen.len()));
    }
    if seen[0].method != method.as_str() || seen[0].body != body.to_string().into_bytes() {
        return Some(format!("not received as sent: {:?}", seen[0]));
    }
    let Err(error) = result else {
        return Some("not refused".into());
    };
    let text = format!("{error:#}");
    if !text.contains(&status.to_string()) || !text.contains("the write was not repeated") {
        return Some(format!(
            "refusal does not name the status and that the write was not repeated: {text}"
        ));
    }
    assert_location_withheld(&text);
    None
}

#[test]
fn a_write_answered_with_a_redirect_is_sent_once_and_refused() {
    let mut failures = Vec::new();
    for status in REDIRECTS {
        for method in WRITES {
            let server = Server::start(move |seen, _| {
                if seen.target == FIRST {
                    Answer::redirect(status, format!("{SECOND}?note={MARKER}"))
                } else {
                    Answer::json(json!({"repeated": true}))
                }
            });
            let body = json!({"title": "a write"});
            let result = server
                .github()
                .api_response(method.clone(), FIRST, Some(&body));
            if let Some(failure) = write_failure(&method, &body, &server.seen(), result, status) {
                failures.push(format!("{method} answered {status}: {failure}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} writes:\n{}",
        failures.len(),
        REDIRECTS.len() * WRITES.len(),
        failures.join("\n")
    );
}

#[test]
fn a_write_redirected_to_another_host_reaches_it_never() {
    let other = other_host();
    let other_port = other.port;
    let mut failures = Vec::new();
    for status in [307, 308] {
        for method in WRITES {
            let server = Server::start(move |_, _| {
                Answer::redirect(status, format!("http://127.0.0.1:{other_port}{FIRST}"))
            });
            let before = other.seen().len();
            let body = json!({"a": 1});
            let result = server
                .github()
                .api_response(method.clone(), FIRST, Some(&body));
            let case = format!("{method} answered {status} to another host");
            let reached = other.seen()[before..].to_vec();
            if reached.iter().any(|r| r.authorization.is_some()) {
                failures.push(format!(
                    "{case}: it received the authorization: {reached:?}"
                ));
            } else if !reached.is_empty() {
                failures.push(format!("{case}: it received the write: {reached:?}"));
            } else if let Some(failure) =
                write_failure(&method, &body, &server.seen(), result, status)
            {
                failures.push(format!("{case}: {failure}"));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// GitHub answers a read of a renamed or transferred repository with a redirect to
/// `/repositories/<id>`; that read keeps working.
#[test]
fn a_read_redirect_to_an_admitted_path_on_the_api_host_is_followed() {
    for status in REDIRECTS {
        for (method, absolute) in [
            (Method::GET, true),
            (Method::GET, false),
            (Method::HEAD, true),
        ] {
            let server = Server::start(move |seen, port| {
                if seen.target == "/repos/example/old-name" {
                    let path = "/repositories/42?per_page=100";
                    if absolute {
                        Answer::redirect(status, format!("http://127.0.0.1:{port}{path}"))
                    } else {
                        Answer::redirect(status, path)
                    }
                } else {
                    Answer::json(json!({"id": 42}))
                }
            });
            let case = format!("{method} answered {status}, absolute Location {absolute}");
            let (answered, value) = server
                .github()
                .api_response(method.clone(), "/repos/example/old-name", None)
                .unwrap_or_else(|error| panic!("{case}: {error:#}"));
            assert_eq!(answered.as_u16(), 200, "{case}");
            if method == Method::GET {
                assert_eq!(value, json!({"id": 42}), "{case}");
            }
            let seen = server.seen();
            let targets: Vec<_> = seen.iter().map(|r| r.target.as_str()).collect();
            assert_eq!(
                targets,
                ["/repos/example/old-name", "/repositories/42?per_page=100"],
                "{case}"
            );
            for request in &seen {
                assert_eq!(request.method, method.as_str(), "{case}");
                assert_eq!(
                    request.authorization.as_deref(),
                    Some("Bearer synthetic-token"),
                    "{case}: the API host itself must still receive the credential"
                );
            }
        }
    }
}

#[test]
fn a_read_redirect_anywhere_else_is_refused_and_never_requested() {
    let other = other_host();
    let other_port = other.port;
    let locations = [
        // `api_path_admitted` refuses `..`; the segment is not a dot segment, so the URL
        // parser keeps it as written.
        (
            "a `..` path",
            format!("/repos/example/repository/..%2f{MARKER}"),
        ),
        // The URL parser would remove the dot segments: `/repos/app/installations`.
        (
            "dot segments",
            format!("/repos/example/repository/../../app/installations?{MARKER}"),
        ),
        ("a fragment", format!("/repositories/42?{MARKER}#part")),
        ("a relative path", format!("repositories/42?{MARKER}")),
        (
            "another host, scheme-relative",
            format!("//127.0.0.1:{other_port}/repositories/42?{MARKER}"),
        ),
        (
            "another host",
            format!("http://127.0.0.1:{other_port}/repositories/42?{MARKER}"),
        ),
        (
            "credentials in the URL",
            format!("http://{TOKEN}@127.0.0.1:PORT/repositories/42?{MARKER}"),
        ),
    ];
    let mut failures = Vec::new();
    for status in REDIRECTS {
        for (what, location) in &locations {
            let location = location.clone();
            let server = Server::start(move |seen, port| {
                if seen.target == FIRST {
                    Answer::redirect(status, location.replace("PORT", &port.to_string()))
                } else {
                    Answer::json(json!({"followed": true}))
                }
            });
            let before = other.seen().len();
            let result = server.github().api_response(Method::GET, FIRST, None);
            let seen = server.seen();
            let reached = other.seen()[before..].to_vec();
            let case = format!("GET answered {status} to {what}");
            if reached.iter().any(|r| r.authorization.is_some()) {
                failures.push(format!(
                    "{case}: another host received the authorization: {reached:?}"
                ));
                continue;
            }
            if !reached.is_empty() || seen.iter().any(|r| r.target != FIRST) {
                failures.push(format!(
                    "{case}: a refused redirect was requested: {seen:?} {reached:?}"
                ));
                continue;
            }
            let Err(error) = result else {
                failures.push(format!("{case}: not refused"));
                continue;
            };
            let text = format!("{error:#}");
            if seen.len() != 1
                || !text.contains(&status.to_string())
                || !text.contains("redirect was not followed")
            {
                failures.push(format!("{case}: sent {} times: {text}", seen.len()));
            }
            assert_location_withheld(&text);
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} reads:\n{}",
        failures.len(),
        REDIRECTS.len() * locations.len(),
        failures.join("\n")
    );
}

#[test]
fn a_read_follows_at_most_ten_redirects() {
    let server = Server::start(|seen, _| {
        let hop: u32 = seen
            .target
            .rsplit('/')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        Answer::redirect(301, format!("/repos/example/repository/hop/{}", hop + 1))
    });
    let result = server
        .github()
        .api_response(Method::GET, "/repos/example/repository/hop/0", None);
    let Err(error) = result else {
        panic!("an endless redirect chain was not refused");
    };
    assert!(
        format!("{error:#}").contains("redirect was not followed"),
        "{error:#}"
    );
    assert_eq!(
        server.seen().len(),
        11,
        "the first request and ten redirects"
    );
}
