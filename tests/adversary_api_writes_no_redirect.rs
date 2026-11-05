//! Adversary cases for `story:api-writes-no-redirect`: every 3xx to a write, unusual 3xx to
//! a read, missing and non-UTF-8 `Location`, `Location` forms the URL parser rewrites, the
//! redirect limit's boundary, loops, and the 5xx GET retry composed with redirects. A
//! plain-HTTP loopback server answers as GitHub through `Github::for_loopback_test`.
use b10x_gates::delivery::Github;
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
};

const TOKEN: &str = "adversary-token";
const FIRST: &str = "/repos/example/repository/first";
const SECOND: &str = "/repos/example/repository/second";
const MARKER: &str = "adversary-marker";

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

/// An answer: status and the raw bytes of a `Location` value, if any.
struct Answer {
    status: u16,
    location: Option<Vec<u8>>,
    body: String,
}

fn redirect(status: u16, location: impl AsRef<[u8]>) -> Answer {
    Answer {
        status,
        location: Some(location.as_ref().to_vec()),
        body: String::new(),
    }
}

fn bare(status: u16) -> Answer {
    Answer {
        status,
        location: None,
        body: String::new(),
    }
}

fn ok(body: Value) -> Answer {
    Answer {
        status: 200,
        location: None,
        body: body.to_string(),
    }
}

struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
}

impl Server {
    fn start(answer: impl Fn(&Seen, u16, usize) -> Answer + Send + 'static) -> Self {
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
                let index = {
                    let mut log = log.lock().unwrap();
                    log.push(request.clone());
                    log.len() - 1
                };
                let reply = answer(&request, port, index);
                let mut head = format!("HTTP/1.1 {} Answer\r\n", reply.status).into_bytes();
                if let Some(location) = &reply.location {
                    head.extend_from_slice(b"Location: ");
                    head.extend_from_slice(location);
                    head.extend_from_slice(b"\r\n");
                }
                head.extend_from_slice(
                    format!(
                        "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        reply.body.len()
                    )
                    .as_bytes(),
                );
                let _ = stream.write_all(&head);
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

fn targets(seen: &[Seen]) -> Vec<String> {
    seen.iter().map(|r| r.target.clone()).collect()
}

/// Every 3xx status, with and without a `Location`, to every non-read method: sent once,
/// body as written, refused naming the method and the status, `Location` withheld.
#[test]
fn every_3xx_to_a_write_is_sent_once_and_refused_naming_method_and_status() {
    let methods = [
        Method::POST,
        Method::PUT,
        Method::PATCH,
        Method::DELETE,
        Method::OPTIONS,
    ];
    let statuses = [300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 399];
    let mut failures = Vec::new();
    for status in statuses {
        for with_location in [true, false] {
            for method in methods.clone() {
                let server = Server::start(move |seen, _, _| {
                    if seen.target == FIRST {
                        if with_location {
                            redirect(status, format!("{SECOND}?{MARKER}"))
                        } else {
                            bare(status)
                        }
                    } else {
                        ok(json!({"repeated": true}))
                    }
                });
                let body = json!({"a": "write"});
                let result = server
                    .github()
                    .api_response(method.clone(), FIRST, Some(&body));
                let seen = server.seen();
                let case = format!("{method} answered {status} (Location {with_location})");
                if targets(&seen) != [FIRST] {
                    failures.push(format!("{case}: sent {:?}", targets(&seen)));
                    continue;
                }
                if seen[0].body != body.to_string().into_bytes() {
                    failures.push(format!("{case}: body not as sent"));
                }
                match result {
                    Ok(_) => failures.push(format!("{case}: not refused")),
                    Err(error) => {
                        let text = format!("{error:#}");
                        if !text.contains(method.as_str())
                            || !text.contains(&status.to_string())
                            || !text.contains("the write was not repeated")
                            || text.contains(MARKER)
                            || text.contains("second")
                        {
                            failures.push(format!("{case}: refusal text: {text}"));
                        }
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A 300, 304 or other 3xx outside 301/302/303/307/308 to a read is not followed, even
/// with an admitted `Location`, and is answered as that status, `Location` withheld.
#[test]
fn an_unfollowed_3xx_to_a_read_is_not_followed_and_names_its_status() {
    let mut failures = Vec::new();
    for status in [300, 304, 305, 306, 309, 399] {
        for with_location in [true, false] {
            for method in [Method::GET, Method::HEAD] {
                let server = Server::start(move |seen, _, _| {
                    if seen.target == FIRST {
                        if with_location {
                            redirect(status, format!("{SECOND}?{MARKER}"))
                        } else {
                            bare(status)
                        }
                    } else {
                        ok(json!({"followed": true}))
                    }
                });
                let result = server.github().api_response(method.clone(), FIRST, None);
                let seen = server.seen();
                let case = format!("{method} answered {status} (Location {with_location})");
                if targets(&seen) != [FIRST] {
                    failures.push(format!("{case}: sent {:?}", targets(&seen)));
                    continue;
                }
                match result {
                    Ok(answer) => failures.push(format!("{case}: answered {answer:?}")),
                    Err(error) => {
                        let text = format!("{error:#}");
                        if !text.contains(&status.to_string()) || text.contains(MARKER) {
                            failures.push(format!("{case}: refusal text: {text}"));
                        }
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A followed status with no `Location`, an empty one, or one that is not UTF-8 or not
/// visible ASCII is refused, sent once.
#[test]
fn a_read_redirect_without_a_usable_location_is_refused() {
    let locations: [(&str, Option<Vec<u8>>); 4] = [
        ("missing", None),
        ("empty", Some(Vec::new())),
        ("not UTF-8", Some(b"/repositories/42?\xff\xfe".to_vec())),
        (
            "UTF-8, not ASCII",
            Some("/repositories/42?\u{e9}".as_bytes().to_vec()),
        ),
    ];
    let mut failures = Vec::new();
    for status in [301, 302, 303, 307, 308] {
        for (what, location) in &locations {
            let location = location.clone();
            let server = Server::start(move |seen, _, _| {
                if seen.target == FIRST {
                    Answer {
                        status,
                        location: location.clone(),
                        body: String::new(),
                    }
                } else {
                    ok(json!({"followed": true}))
                }
            });
            let result = server.github().api_response(Method::GET, FIRST, None);
            let seen = server.seen();
            let case = format!("GET answered {status}, Location {what}");
            if targets(&seen) != [FIRST] {
                failures.push(format!("{case}: sent {:?}", targets(&seen)));
                continue;
            }
            match result {
                Ok(answer) => failures.push(format!("{case}: answered {answer:?}")),
                Err(error) => {
                    let text = format!("{error:#}");
                    if !text.contains(&status.to_string())
                        || !text.contains("redirect was not followed")
                        || !text.contains("GET")
                    {
                        failures.push(format!("{case}: refusal text: {text}"));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// `Location` forms that are not exactly the path or the API-host URL: percent-encoded dot
/// segments, scheme-relative same host, userinfo, a port written differently, uppercase
/// scheme or host, IPv6, other scheme, backslash, tab, integer host, trailing dot. None is
/// requested; another host never sees a request.
#[test]
fn a_read_redirect_not_written_exactly_as_requested_is_refused() {
    let other = Server::start(|_, _, _| ok(json!({"other": true})));
    let other_port = other.port;
    let locations = [
        "/repos/example/%2e%2e/app/installations?M",
        "/repos/example/%2E%2E/app/installations?M",
        "/repos/example/.%2e/app/installations?M",
        "/repos/example/%2e./app/installations?M",
        "/repos/example/%2e/repositories/42?M",
        "/repos/example/./repositories/42?M",
        "//127.0.0.1:PORT/repositories/42?M",
        "//127.0.0.1:OTHER/repositories/42?M",
        "HTTP://127.0.0.1:PORT/repositories/42?M",
        "Http://127.0.0.1:PORT/repositories/42?M",
        "http://127.0.0.1:0PORT/repositories/42?M",
        "http://127.0.0.1:OTHER/repositories/42?M",
        "http://user@127.0.0.1:PORT/repositories/42?M",
        "http://user:pw@127.0.0.1:PORT/repositories/42?M",
        "http://@127.0.0.1:PORT/repositories/42?M",
        "http://[::1]:PORT/repositories/42?M",
        "http://[::ffff:127.0.0.1]:PORT/repositories/42?M",
        "http://localhost:PORT/repositories/42?M",
        "http://LOCALHOST:PORT/repositories/42?M",
        "http://127.0.0.1.:PORT/repositories/42?M",
        "http://2130706433:PORT/repositories/42?M",
        "http://0x7f.0.0.1:PORT/repositories/42?M",
        "https://127.0.0.1:PORT/repositories/42?M",
        "ftp://127.0.0.1:PORT/repositories/42?M",
        "/\\127.0.0.1:OTHER/repositories/42?M",
        "\\\\127.0.0.1:OTHER/repositories/42?M",
        "/repositories/4\t2?M",
        "/repositories/42?M#",
        "?M",
        "./second?M",
        "http://127.0.0.1:PORT",
        "http://127.0.0.1:PORT/repos/x/../repositories/42?M",
        "http://127.0.0.1:PORT/repos/x/%2e%2e/repositories/42?M",
    ];
    let mut failures = Vec::new();
    for status in [301, 302, 303, 307, 308] {
        for template in locations {
            let written = template.to_owned();
            let server = Server::start(move |seen, port, _| {
                if seen.target == FIRST {
                    let location = written
                        .replace("OTHER", &other_port.to_string())
                        .replace("PORT", &port.to_string())
                        .replace('M', MARKER);
                    redirect(status, location)
                } else {
                    ok(json!({"followed": true}))
                }
            });
            let before = other.seen().len();
            let result = server.github().api_response(Method::GET, FIRST, None);
            let seen = server.seen();
            let reached = other.seen()[before..].to_vec();
            let case = format!("GET answered {status} to {template:?}");
            if !reached.is_empty() {
                failures.push(format!("{case}: another host received {reached:?}"));
                continue;
            }
            if targets(&seen) != [FIRST] {
                failures.push(format!("{case}: sent {:?}", targets(&seen)));
                continue;
            }
            match result {
                Ok(answer) => failures.push(format!("{case}: answered {answer:?}")),
                Err(error) => {
                    let text = format!("{error:#}");
                    if !text.contains(&status.to_string())
                        || !text.contains("redirect was not followed")
                        || text.contains(MARKER)
                    {
                        failures.push(format!("{case}: refusal text: {text}"));
                    }
                }
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The limit's boundary: exactly ten redirects then an answer is followed to the end, with
/// the credential on every hop of the API host.
#[test]
fn a_read_of_exactly_ten_redirects_is_followed() {
    let server = Server::start(|seen, _, _| {
        let hop: u32 = seen
            .target
            .rsplit('/')
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        if hop == 10 {
            ok(json!({"hop": hop}))
        } else {
            redirect(307, format!("/repos/example/repository/hop/{}", hop + 1))
        }
    });
    let (status, value) = server
        .github()
        .api_response(Method::GET, "/repos/example/repository/hop/0", None)
        .unwrap_or_else(|error| panic!("ten redirects: {error:#}"));
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value, json!({"hop": 10}));
    let seen = server.seen();
    assert_eq!(seen.len(), 11);
    for request in &seen {
        assert_eq!(request.method, "GET");
        assert_eq!(
            request.authorization.as_deref(),
            Some("Bearer adversary-token")
        );
    }
}

/// A `Location` naming the request itself, and a two-step cycle, stop after ten follows
/// and are not retried as server errors.
#[test]
fn a_redirect_loop_is_refused_after_ten_follows() {
    for (what, cycle) in [("itself", false), ("a two-step cycle", true)] {
        let server = Server::start(move |seen, port, _| {
            let next = if cycle && seen.target == FIRST {
                SECOND
            } else {
                FIRST
            };
            redirect(308, format!("http://127.0.0.1:{port}{next}"))
        });
        let result = server.github().api_response(Method::GET, FIRST, None);
        let Err(error) = result else {
            panic!("{what}: a loop was not refused");
        };
        let text = format!("{error:#}");
        assert!(
            text.contains("308") && text.contains("redirect was not followed"),
            "{what}: {text}"
        );
        assert_eq!(server.seen().len(), 11, "{what}: {:?}", server.seen());
    }
}

/// A redirect whose target answers 5xx: the GET is retried, each attempt from the path the
/// caller requested and through the redirect again, five attempts in all, and the last
/// answer is the server error.
#[test]
fn a_redirect_then_a_server_error_is_retried_from_the_requested_path() {
    let server = Server::start(|seen, _, _| {
        if seen.target == FIRST {
            redirect(301, SECOND)
        } else {
            bare(502)
        }
    });
    let result = server.github().api_response(Method::GET, FIRST, None);
    let Err(error) = result else {
        panic!("a persistent 502 was not refused");
    };
    assert!(format!("{error:#}").contains("502"), "{error:#}");
    let seen = server.seen();
    let expected: Vec<String> = (0..5)
        .flat_map(|_| [FIRST.to_owned(), SECOND.to_owned()])
        .collect();
    assert_eq!(targets(&seen), expected);
    assert!(
        seen.iter()
            .all(|r| r.authorization.as_deref() == Some("Bearer adversary-token"))
    );
}

/// A 5xx first, then a redirect, then an answer; and a redirect, then a 5xx at the target,
/// then an answer: both succeed with the target's answer.
#[test]
fn a_server_error_and_a_redirect_compose_in_either_order() {
    let first_errs = Server::start(|seen, _, index| {
        if seen.target == FIRST && index == 0 {
            bare(500)
        } else if seen.target == FIRST {
            redirect(302, SECOND)
        } else {
            ok(json!({"at": "second"}))
        }
    });
    let (_, value) = first_errs
        .github()
        .api_response(Method::GET, FIRST, None)
        .unwrap_or_else(|error| panic!("5xx then redirect: {error:#}"));
    assert_eq!(value, json!({"at": "second"}));
    assert_eq!(targets(&first_errs.seen()), [FIRST, FIRST, SECOND]);

    let second_hits = Arc::new(AtomicUsize::new(0));
    let hits = Arc::clone(&second_hits);
    let second_errs = Server::start(move |seen, _, _| {
        if seen.target == FIRST {
            redirect(307, SECOND)
        } else if hits.fetch_add(1, Ordering::SeqCst) == 0 {
            bare(503)
        } else {
            ok(json!({"at": "second"}))
        }
    });
    let (_, value) = second_errs
        .github()
        .api_response(Method::GET, FIRST, None)
        .unwrap_or_else(|error| panic!("redirect then 5xx: {error:#}"));
    assert_eq!(value, json!({"at": "second"}));
    assert_eq!(targets(&second_errs.seen()), [FIRST, SECOND, FIRST, SECOND]);
}

/// A write answered 5xx after nothing else is sent once, not retried, and a write never
/// follows a redirect into a retried 5xx.
#[test]
fn a_write_answered_with_a_server_error_or_a_redirect_is_sent_once() {
    for method in [Method::POST, Method::PATCH, Method::DELETE] {
        for first in [500u16, 307] {
            let server = Server::start(move |seen, _, _| {
                if seen.target == FIRST {
                    if first == 307 {
                        redirect(307, SECOND)
                    } else {
                        bare(first)
                    }
                } else {
                    bare(500)
                }
            });
            let result = server
                .github()
                .api_response(method.clone(), FIRST, Some(&json!({})));
            assert!(result.is_err(), "{method} answered {first}");
            assert_eq!(
                targets(&server.seen()),
                [FIRST],
                "{method} answered {first}"
            );
        }
    }
}
