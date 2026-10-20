//! `gates.delivery.BotApi`: the bot never changes a ruleset or branch protection. The App
//! holds `administration`, so a bot write there could loosen the protection that limits
//! the bot. `b10x-gates api` and `b10x-gates gh -- api` ask these functions before the
//! policy is read and before a token is minted; reads stay open.

/// The cause every refusal states.
pub const OWNERS: &str = "ruleset and branch protection changes are the owner's";

/// The GraphQL mutations that change a ruleset or branch protection.
pub const MUTATIONS: [&str; 6] = [
    "createRepositoryRuleset",
    "updateRepositoryRuleset",
    "deleteRepositoryRuleset",
    "createBranchProtectionRule",
    "updateBranchProtectionRule",
    "deleteBranchProtectionRule",
];

/// Longest path shown in a refusal, in characters.
const SHOWN: usize = 300;

/// `b10x-gates api`: the refusal for a request that would change a ruleset or branch
/// protection, or `None`. A write is any method but GET and HEAD, compared
/// case-insensitively. Refused: a write to a protection path in any reading of `path`
/// (`protected`); a write whose path cannot be decoded; and a `/graphql` request, whatever
/// the method, whose body names one of `MUTATIONS`.
pub fn protection_write(method: &str, path: &str, body: &[u8]) -> Option<String> {
    let write = !(method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD"));
    let request = format!("{} {}", shown(method), shown(path));
    let mutation = || mutations(body);
    let Some(readings) = readings(path, true) else {
        return (write || mutation().is_some()).then(|| {
            format!(
                "{request} refused: the path cannot be decoded (a `%` that is not an escape, \
                 or bytes that are not UTF-8), so it cannot be shown to leave rulesets and \
                 branch protection alone; {OWNERS}"
            )
        });
    };
    if write && readings.iter().any(|segments| protected(segments)) {
        return Some(format!(
            "{request} refused: it writes to a ruleset or to branch protection; {OWNERS}; \
             read them with --method GET"
        ));
    }
    if readings
        .iter()
        .any(|segments| segments.len() == 1 && fixed(&segments[0], "graphql"))
        && let Some(name) = mutation()
    {
        return Some(format!(
            "{request} refused: the GraphQL request names the mutation {name}; {OWNERS}"
        ));
    }
    None
}

/// `b10x-gates gh -- api`: the refusal for an argument, or a file an argument names, that
/// carries a protection path or one of `MUTATIONS`, whatever the method, or `None`.
/// `args` is the whole command, `api` first, so argument numbers match the private-rule
/// scan's. `read` reads a named file as `gh` would; a file it cannot read, and standard
/// input, cannot be judged and are refused.
pub fn gh_api_refusal(
    args: &[String],
    read: impl Fn(&str) -> std::io::Result<Vec<u8>>,
) -> Option<String> {
    for (i, argument) in args.iter().enumerate() {
        if let Some(found) = carried(argument.as_bytes()).or_else(|| placeholder(argument)) {
            return Some(format!(
                "gh api argument {} {found}; {OWNERS}; read them with `b10x-gates api \
                 --method GET`",
                i + 1
            ));
        }
    }
    for (i, file) in gh_api_files(args) {
        let named = format!(
            "gh api argument {}, the file it names ({}),",
            i + 1,
            shown(&file)
        );
        if file == "-" {
            return Some(format!(
                "gh api argument {} reads standard input, which cannot be checked for a \
                 ruleset or branch protection change; {OWNERS}: name a file instead",
                i + 1
            ));
        }
        let bytes = match read(&file) {
            Ok(bytes) => bytes,
            Err(error) => {
                return Some(format!(
                    "{named} cannot be read ({error}), so it cannot be checked for a ruleset \
                     or branch protection change; {OWNERS}"
                ));
            }
        };
        if let Some(found) = carried(&bytes) {
            return Some(format!("{named} {found}; {OWNERS}"));
        }
    }
    None
}

/// The files `gh api` reads for its arguments, each with the index of the argument that
/// names it: `--input <file>`, `--input=<file>`, and the `@<file>` value of a field in each
/// spelling `gh` accepts: `-F k=@f`, `-Fk=@f`, `-F=k=@f`, a short cluster ending in or
/// holding `F` (`-iF k=@f`), `--field k=@f` and `--field=k=@f`. `-` is standard input.
/// Every argument is read as a possible flag, so a value another flag consumes can only
/// add a file, never hide one.
pub fn gh_api_files(args: &[String]) -> Vec<(usize, String)> {
    let field = |pair: &str| {
        pair.split_once('=')
            .and_then(|(_, value)| value.strip_prefix('@'))
            .map(str::to_owned)
    };
    let mut files = Vec::new();
    for (i, argument) in args.iter().enumerate() {
        let next = args.get(i + 1).map(|n| (i + 1, n.as_str()));
        if argument == "--input" {
            files.extend(next.map(|(j, n)| (j, n.to_owned())));
        } else if let Some(file) = argument.strip_prefix("--input=") {
            files.push((i, file.to_owned()));
        } else if argument == "--field" {
            files.extend(next.and_then(|(j, n)| field(n).map(|f| (j, f))));
        } else if let Some(pair) = argument.strip_prefix("--field=") {
            files.extend(field(pair).map(|f| (i, f)));
        } else if let Some(cluster) = argument.strip_prefix('-').filter(|c| !c.starts_with('-')) {
            for (at, flag) in cluster.char_indices() {
                if flag == 'F' {
                    let rest = &cluster[at + 1..];
                    let rest = rest.strip_prefix('=').unwrap_or(rest);
                    if rest.is_empty() {
                        files.extend(next.and_then(|(j, n)| field(n).map(|f| (j, f))));
                    } else {
                        files.extend(field(rest).map(|f| (i, f)));
                    }
                    break;
                }
                // The other short flags of `gh api` that take a value: the rest of the
                // cluster, or the next argument, is that value.
                if "fHXqtp".contains(flag) {
                    break;
                }
            }
        }
    }
    files
}

/// What `gh` fills into the endpoint and into `-F` values once the guard has read them:
/// the repository's owner and name, which `gh` refuses to hold `/`, and the current
/// branch, whose name may.
const PLACEHOLDERS: [&str; 6] = [
    "{owner}", "{repo}", "{branch}", ":owner", ":repo", ":branch",
];

/// What a segment holding an owner or name placeholder is tried as: another name, a dot
/// segment, and each fixed segment of a protection path.
const STAND_INS: [&str; 10] = [
    "x",
    ".",
    "..",
    "repos",
    "repositories",
    "orgs",
    "organizations",
    "rulesets",
    "branches",
    "protection",
];

/// Most segments holding a placeholder one argument is judged with, so at most
/// `STAND_INS.len()` to this power fillings are tried; more are refused.
const MOST_PLACEHOLDER_SEGMENTS: u32 = 4;

/// An argument whose placeholders `gh` could fill into a protection path or a mutation
/// name, as the clause of a refusal. Refused: a placeholder in an argument that names a
/// GraphQL `query`; `{branch}` anywhere but as a whole field value (`head={branch}`),
/// since the branch name may hold `/`; and an argument that, read as the endpoint, is a
/// protection path for some owner or name, each segment holding one tried as every
/// `STAND_INS`. A field value `<key>=<placeholder>` is admitted: its first segment
/// starts with `<key>=`, which no fixed segment does.
fn placeholder(argument: &str) -> Option<String> {
    let text = argument.to_lowercase();
    if !PLACEHOLDERS.iter().any(|p| text.contains(p)) {
        return None;
    }
    if text.contains("query") {
        return Some(
            "fills a placeholder into a GraphQL query, where a value the guard cannot see \
             could complete a mutation name"
                .into(),
        );
    }
    if let Some((key, value)) = text.rsplit_once('=')
        && PLACEHOLDERS.contains(&value)
        && !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-[]=".contains(c))
    {
        return None;
    }
    if text.contains("{branch}") || text.contains(":branch") {
        return Some(
            "holds the {branch} placeholder, which gh fills with the current branch name; \
             it may hold `/` and become any path, so name the branch instead"
                .into(),
        );
    }
    let path = match text.find("://") {
        Some(at) => text[at + 3..].find('/').map_or("", |s| &text[at + 3 + s..]),
        None => text.as_str(),
    };
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let segments: Vec<&str> = path.split(['/', '\\']).collect();
    let holes: Vec<usize> = (0..segments.len())
        .filter(|&i| PLACEHOLDERS.iter().any(|p| segments[i].contains(p)))
        .collect();
    let count = u32::try_from(holes.len()).unwrap_or(u32::MAX);
    if count > MOST_PLACEHOLDER_SEGMENTS {
        return Some("holds more placeholders than the guard can judge".into());
    }
    for n in 0..STAND_INS.len().pow(count) {
        let mut filled = segments.clone();
        let mut rest = n;
        for &hole in &holes {
            filled[hole] = STAND_INS[rest % STAND_INS.len()];
            rest /= STAND_INS.len();
        }
        let candidate = filled.join("/");
        if readings(&candidate, false)
            .unwrap_or_default()
            .iter()
            .any(|segments| protected(segments))
        {
            return Some(format!(
                "becomes a protection path once gh fills its placeholders (as {})",
                shown(&candidate)
            ));
        }
    }
    None
}

/// What a text carries, as the clause of a refusal: a protection path in any reading, or
/// one of `MUTATIONS`.
fn carried(bytes: &[u8]) -> Option<String> {
    let views = views(bytes);
    for view in &views {
        if let Some(path) = paths(view).into_iter().find(|p| {
            readings(p, false)
                .unwrap_or_default()
                .iter()
                .any(|segments| protected(segments))
        }) {
            return Some(format!("carries the protection path {}", shown(&path)));
        }
    }
    mutations(bytes).map(|name| format!("names the GraphQL mutation {name}"))
}

/// The first of `MUTATIONS` a text names, in any case, also behind a JSON `\u` escape or
/// percent-encoding.
fn mutations(bytes: &[u8]) -> Option<&'static str> {
    let views = views(bytes);
    MUTATIONS
        .into_iter()
        .find(|name| views.iter().any(|v| v.contains(&name.to_lowercase())))
}

/// A text with JSON's `\uXXXX` and `\/` escapes undone and as given, each then
/// percent-decoded until stable (an escape that does not decode stays as it is), all
/// lowercased.
fn views(bytes: &[u8]) -> Vec<String> {
    let raw = String::from_utf8_lossy(bytes).into_owned();
    let unescaped = json_unescaped(&raw);
    let mut views = Vec::new();
    for start in [unescaped, raw] {
        for stage in stages(&start, false).unwrap_or_default() {
            views.push(stage.to_lowercase());
        }
    }
    views.dedup();
    views
}

/// Every place in a lowercased text where a REST path of a protection family may begin
/// (`repos`, `repositories`, `orgs`, `organizations`, not inside a longer word), up to
/// the next space, quote or angle bracket, as an absolute path.
fn paths(view: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut previous: Option<char> = None;
    for (at, c) in view.char_indices() {
        let rest = &view[at..];
        if !previous.is_some_and(|p| p.is_alphanumeric())
            && (rest.starts_with("repos") || rest.starts_with("org"))
        {
            let end = rest
                .find(|c: char| c.is_whitespace() || "\"'`<>".contains(c))
                .unwrap_or(rest.len());
            found.push(format!("/{}", &rest[..end]));
        }
        previous = Some(c);
    }
    found
}

/// Every reading of a path a server on the way may make, each as its segments: as given
/// and after each percent-decoding until stable; lowercased; tab and newline removed (the
/// URL parser drops them); `\` as a separator (the URL parser reads it as `/`); with and
/// without what follows `?` or `#`; empty segments dropped (repeated and trailing
/// separators); each segment trimmed; `.` and `..` segments kept and resolved. `None`
/// when `strict` and a decoding fails.
fn readings(path: &str, strict: bool) -> Option<Vec<Vec<String>>> {
    let mut readings = Vec::new();
    for stage in stages(path, strict)? {
        let text: String = stage
            .chars()
            .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
            .collect::<String>()
            .to_lowercase();
        let cut = text.split(['?', '#']).next().unwrap_or_default();
        for candidate in [text.as_str(), cut] {
            let segments: Vec<String> = candidate
                .split(['/', '\\'])
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_owned())
                .collect();
            let mut resolved: Vec<String> = Vec::new();
            for segment in &segments {
                match segment.as_str() {
                    "." => {}
                    ".." => {
                        resolved.pop();
                    }
                    _ => resolved.push(segment.clone()),
                }
            }
            readings.push(segments);
            readings.push(resolved);
        }
    }
    Some(readings)
}

/// A path's segments name a protection surface: `repos/<o>/<r>` or `repositories/<id>`
/// followed by `rulesets`, or by `branches/<branch...>/protection` with anything below;
/// or `orgs/<o>` or `organizations/<id>` followed by `rulesets`.
fn protected(segments: &[String]) -> bool {
    let Some(first) = segments.first() else {
        return false;
    };
    let rest = if fixed(first, "repos") && segments.len() > 3 {
        &segments[3..]
    } else if fixed(first, "repositories") && segments.len() > 2 {
        &segments[2..]
    } else if fixed(first, "orgs") || fixed(first, "organizations") {
        return segments.get(2).is_some_and(|s| fixed(s, "rulesets"));
    } else {
        return false;
    };
    if fixed(&rest[0], "rulesets") {
        return true;
    }
    // A branch name may hold `/`, so `protection` anywhere after its first segment counts.
    fixed(&rest[0], "branches") && rest.iter().skip(2).any(|s| fixed(s, "protection"))
}

/// A fixed segment, alone or with a suffix a router may strip: a format (`rulesets.json`),
/// matrix parameters (`rulesets;x`), or trailing white space or control characters.
fn fixed(segment: &str, name: &str) -> bool {
    segment.strip_prefix(name).is_some_and(|rest| {
        rest.chars()
            .next()
            .is_none_or(|c| matches!(c, '.' | ';') || c.is_whitespace() || c.is_control())
    })
}

/// The text and each percent-decoding of it until stable. Strict: a `%` that is not an
/// escape, or bytes that are not UTF-8, fail; lenient: such a `%` stays, and invalid bytes
/// become U+FFFD.
fn stages(text: &str, strict: bool) -> Option<Vec<String>> {
    let mut stages = vec![text.to_owned()];
    loop {
        let last = stages.last().expect("one stage");
        let next = decoded(last, strict)?;
        if next == *last {
            return Some(stages);
        }
        stages.push(next);
    }
}

fn decoded(text: &str, strict: bool) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            // Two hex digits exactly: `from_str_radix` alone would take `%+1`.
            let hex = bytes
                .get(i + 1..i + 3)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                .and_then(|h| std::str::from_utf8(h).ok())
                .and_then(|h| u8::from_str_radix(h, 16).ok());
            match hex {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                    continue;
                }
                None if strict => return None,
                None => {}
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    if strict {
        String::from_utf8(out).ok()
    } else {
        Some(String::from_utf8_lossy(&out).into_owned())
    }
}

/// JSON's `\uXXXX` (a scalar value, not a surrogate) and `\/` escapes undone, anywhere in
/// the text, so an escaped name or path is read as the JSON parser on the server reads it.
fn json_unescaped(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let escape = &rest[at..];
        if let Some(path) = escape.strip_prefix("\\/") {
            out.push('/');
            rest = path;
        } else if let Some(c) = escape
            .get(2..6)
            .filter(|h| escape.starts_with("\\u") && h.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|h| u32::from_str_radix(h, 16).ok())
            .and_then(char::from_u32)
        {
            out.push(c);
            rest = &escape[6..];
        } else {
            out.push('\\');
            rest = &escape[1..];
        }
    }
    out.push_str(rest);
    out
}

/// A caller's text as shown in a refusal: escaped for the terminal, cut to `SHOWN`.
fn shown(text: &str) -> String {
    let escaped: String = text.escape_debug().collect();
    escaped.chars().take(SHOWN).collect()
}
