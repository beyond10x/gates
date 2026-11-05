//! Security review of `story:api-writes-no-redirect`. Two invariants the other suites hold
//! only by example: a write is any method but GET and HEAD written exactly so (the
//! README's words, reached by `api --method <any token>`), and a read follows a redirect
//! only to the `Location` exactly as written, on the API host, to an admitted path, for
//! every `Location` a fixed-seed generator writes. A plain-HTTP loopback server answers as
//! GitHub through `Github::for_loopback_test`.
use b10x_gates::delivery::Github;
use reqwest::Method;
use serde_json::json;
use std::{
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    sync::{Arc, Mutex},
    thread,
};

const TOKEN: &str = "security-review-token";
const FIRST: &str = "/repos/example/repository/first";
const SECOND: &str = "/repos/example/repository/second";
/// Carried in every `Location`; a refusal that shows it shows the `Location`.
const MARKER: &str = "review-marker";
const FOLLOWED: [u16; 5] = [301, 302, 303, 307, 308];

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    target: String,
    authorization: Option<String>,
    body: Vec<u8>,
}

/// A loopback server that answers the request for `FIRST` with `status` and the
/// `Location` currently set, and every other request with 200.
struct Server {
    port: u16,
    seen: Arc<Mutex<Vec<Seen>>>,
    answer: Arc<Mutex<(u16, Option<String>)>>,
}

impl Server {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let answer = Arc::new(Mutex::new((200, None)));
        let (log, current) = (Arc::clone(&seen), Arc::clone(&answer));
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { continue };
                let Some(request) = read_request(&mut stream) else {
                    continue;
                };
                log.lock().unwrap().push(request.clone());
                let (status, location) = if request.target == FIRST {
                    current.lock().unwrap().clone()
                } else {
                    (200, None)
                };
                let body = if status == 200 {
                    json!({"answered": request.target}).to_string()
                } else {
                    String::new()
                };
                let mut head = format!("HTTP/1.1 {status} Answer\r\n");
                if let Some(location) = location {
                    head.push_str(&format!("Location: {location}\r\n"));
                }
                head.push_str(&format!(
                    "Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                ));
                let _ = stream.write_all(head.as_bytes());
                if request.method != "HEAD" {
                    let _ = stream.write_all(body.as_bytes());
                }
                let _ = stream.flush();
            }
        });
        Self { port, seen, answer }
    }

    fn answer(&self, status: u16, location: Option<String>) {
        *self.answer.lock().unwrap() = (status, location);
        self.seen.lock().unwrap().clear();
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

/// The README: "a write (any method but GET and HEAD)". HTTP methods are case-sensitive,
/// and `api --method` parses any token, so `get`, `Head` and an extension method such as
/// `PROPFIND` are writes: answered with a followed status and an admitted same-host
/// `Location`, each is sent once, body as written, and refused saying it was not repeated.
#[test]
fn any_method_but_exact_get_and_head_is_a_write_that_a_redirect_never_repeats() {
    let server = Server::start();
    let methods = [
        "get", "Get", "gET", "head", "Head", "hEAD", "PROPFIND", "QUERY", "LINK", "TRACE",
    ];
    let mut failures = Vec::new();
    for name in methods {
        let method = Method::from_bytes(name.as_bytes()).unwrap();
        for status in FOLLOWED {
            server.answer(status, Some(format!("{SECOND}?{MARKER}")));
            let body = json!({"a": "write"});
            let result = server
                .github()
                .api_response(method.clone(), FIRST, Some(&body));
            let seen = server.seen();
            let case = format!("{name} answered {status}");
            let targets: Vec<&str> = seen.iter().map(|r| r.target.as_str()).collect();
            if targets != [FIRST] {
                failures.push(format!("{case}: sent to {targets:?}"));
                continue;
            }
            if seen[0].method != name || seen[0].body != body.to_string().into_bytes() {
                failures.push(format!("{case}: not sent as written: {:?}", seen[0]));
            }
            match result {
                Ok(answer) => failures.push(format!("{case}: not refused: {answer:?}")),
                Err(error) => {
                    let text = format!("{error:#}");
                    if !text.contains(&status.to_string())
                        || !text.contains("the write was not repeated")
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

/// xorshift64*, so the generated `Location` values are the same on every run.
struct Seed(u64);

impl Seed {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn pick<'a>(&mut self, from: &[&'a str]) -> &'a str {
        from[(self.next() % from.len() as u64) as usize]
    }
}

/// Pieces a `Location` is written from: separators, dot segments plain and
/// percent-encoded, authority syntax, this host and port, another host's port, query and
/// fragment marks, whitespace the parser strips and bytes it re-encodes.
const PIECES: [&str; 34] = [
    "/",
    "//",
    "\\",
    "/repositories/42",
    "/repos/example/repository/",
    "repositories",
    "..",
    ".",
    "../",
    "./",
    "%2e",
    "%2E",
    "%2e%2e/",
    ".%2E/",
    "%2f",
    "%5c",
    "%25",
    "%",
    "?",
    "?q=..",
    "?page=2",
    "#",
    "@",
    ":",
    ";",
    "http://127.0.0.1:PORT",
    "http://127.0.0.1:OTHER",
    "http://user@127.0.0.1:PORT",
    "//127.0.0.1:OTHER",
    "HTTP://127.0.0.1:PORT",
    " ",
    "\t",
    "'",
    "a",
];

/// For every `Location` the generator writes and every followed status: another host is
/// never sent anything; the API host is sent at most one further request, and only when
/// the `Location` is exactly its path or this origin followed by its path, that path
/// absolute with no `..` and no `#`, carrying the credential; otherwise the read is
/// refused naming its status, `Location` withheld.
#[test]
fn a_read_follows_only_the_location_exactly_as_written_on_the_api_host() {
    let server = Server::start();
    let other = Server::start();
    let origin = format!("http://127.0.0.1:{}", server.port);
    let mut seed = Seed(0x5eed_0fa1_15ec);
    let mut failures = Vec::new();
    let mut followed = 0;
    let cases = 600;
    for case in 0..cases {
        let pieces = 1 + seed.next() % 6;
        let mut location: String = (0..pieces).map(|_| seed.pick(&PIECES)).collect();
        if seed.next().is_multiple_of(2) {
            location.push_str(&format!("?{MARKER}"));
        }
        let location = location
            .replace("OTHER", &other.port.to_string())
            .replace("PORT", &server.port.to_string());
        let status = FOLLOWED[(seed.next() % FOLLOWED.len() as u64) as usize];
        server.answer(status, Some(location.clone()));
        other.answer(200, None);
        let result = server.github().api_response(Method::GET, FIRST, None);
        let seen = server.seen();
        let what = format!("case {case}: GET answered {status} to {location:?}");
        if !other.seen().is_empty() {
            failures.push(format!("{what}: another host was sent {:?}", other.seen()));
            continue;
        }
        if seen.first().map(|r| r.target.as_str()) != Some(FIRST) || seen.len() > 2 {
            failures.push(format!("{what}: sent {seen:?}"));
            continue;
        }
        if seen
            .iter()
            .any(|r| r.authorization.as_deref() != Some(&format!("Bearer {TOKEN}")))
        {
            failures.push(format!("{what}: credential not as sent: {seen:?}"));
        }
        match (seen.get(1), result) {
            (Some(next), Ok(_)) => {
                followed += 1;
                let target = next.target.as_str();
                let written = location.trim_matches([' ', '\t']);
                let exact = written == target || written == format!("{origin}{target}");
                if !exact
                    || !target.starts_with('/')
                    || target.contains("..")
                    || target.contains('#')
                {
                    failures.push(format!("{what}: followed to {target:?}"));
                }
            }
            (None, Err(error)) => {
                let text = format!("{error:#}");
                if !text.contains(&status.to_string())
                    || !text.contains("redirect was not followed")
                    || text.contains(MARKER)
                {
                    failures.push(format!("{what}: refusal text: {text}"));
                }
            }
            (next, result) => {
                failures.push(format!("{what}: sent {next:?}, answered {result:?}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {cases} reads:\n{}",
        failures.len(),
        failures.join("\n")
    );
    // The generator must reach both outcomes, or the property says nothing about one.
    assert!(
        followed > 20 && followed < cases - 20,
        "{followed} of {cases} reads followed"
    );
}
