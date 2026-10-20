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

/// Most percent-decodings a text is read through. Text still changing after the last of
/// them cannot be decoded and is refused, so the readings kept stay linear in the input.
const MOST_DECODINGS: usize = 8;

/// A text the guard cannot read: an `api` path whose first decoding fails, or any text
/// still changing after `MOST_DECODINGS` decodings.
struct Undecodable;

/// What one `gh api` argument or named file carries: its first protection path as shown
/// and its first mutation, or `None` when it cannot be decoded.
type Found = Option<(Option<String>, Option<&'static str>)>;

/// `b10x-gates api`: the refusal for a request that would change a ruleset or branch
/// protection, or `None`. A write is any method but GET and HEAD, compared
/// case-insensitively. Refused: a write to a protection path in any reading of `path`
/// (`protected`); a write whose path cannot be decoded; and a `/graphql` request, whatever
/// the method, whose body or path (its query string, in every reading) names one of
/// `MUTATIONS` or cannot be decoded.
pub fn protection_write(method: &str, path: &str, body: &[u8]) -> Option<String> {
    let write = !(method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD"));
    let request = format!("{} {}", shown(method), shown(path));
    let mutation = || -> Result<Option<&'static str>, Undecodable> {
        match mutation_in(&views(body).ok_or(Undecodable)?) {
            Some(name) => Ok(Some(name)),
            None => Ok(mutation_in(&views(path.as_bytes()).ok_or(Undecodable)?)),
        }
    };
    let Some(readings) = readings(path, true) else {
        return (write || !matches!(mutation(), Ok(None))).then(|| {
            format!(
                "{request} refused: the path cannot be decoded (a `%` that is not an escape, \
                 or bytes that are not UTF-8, at the first decoding, or text still changing \
                 after {MOST_DECODINGS} decodings), so it cannot be shown to leave rulesets \
                 and branch protection alone; {OWNERS}"
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
    {
        match mutation() {
            Ok(Some(name)) => {
                return Some(format!(
                    "{request} refused: the GraphQL request names the mutation {name}; {OWNERS}"
                ));
            }
            Err(Undecodable) => {
                return Some(format!(
                    "{request} refused: the GraphQL request cannot be decoded within \
                     {MOST_DECODINGS} decodings, so it cannot be shown to name no ruleset or \
                     branch protection mutation; {OWNERS}"
                ));
            }
            Ok(None) => {}
        }
    }
    None
}

/// `b10x-gates gh -- api`: the refusal for an argument, or a file an argument names, that
/// carries a protection path or one of `MUTATIONS`, whatever the method, or `None`.
/// `args` is the whole command, `api` first, so argument numbers match the private-rule
/// scan's. `read` reads a named file as `gh` would. Judged in this order over every
/// argument and named file, so the refusal names what the request changes whenever it
/// names anything: a protection path; a mutation; text that cannot be decoded; standard
/// input and a file that cannot be read; a placeholder `gh` could fill into a protection
/// path or mutation; a body-encoding header text.
pub fn gh_api_refusal(
    args: &[String],
    read: impl Fn(&str) -> std::io::Result<Vec<u8>>,
) -> Option<String> {
    let argument = |i: usize| format!("gh api argument {}", i + 1);
    let mut texts: Vec<(String, Vec<u8>)> = args
        .iter()
        .enumerate()
        .map(|(i, text)| (argument(i), text.as_bytes().to_vec()))
        .collect();
    let files = gh_api_files(args);
    // Standard input across every argument before any file is read, so an unreadable file
    // named earlier is never what the refusal names (round 3, B2).
    let mut uncheckable = files.iter().find(|(_, file)| file == "-").map(|(i, _)| {
        format!(
            "{} reads standard input, which cannot be checked for a ruleset or branch \
             protection change; {OWNERS}: name a file instead",
            argument(*i)
        )
    });
    for (i, file) in files {
        let named = format!("{}, the file it names ({}),", argument(i), shown(&file));
        if file == "-" {
            continue;
        }
        match read(&file) {
            Ok(bytes) => texts.push((named, bytes)),
            Err(error) => {
                uncheckable.get_or_insert(format!(
                    "{named} cannot be read ({error}), so it cannot be checked for a ruleset \
                     or branch protection change; {OWNERS}"
                ));
            }
        }
    }
    // Each text read once.
    let judged: Vec<(&str, Found)> = texts
        .iter()
        .map(|(who, bytes)| {
            let found = views(bytes).map(|views| {
                (
                    views.iter().find_map(|view| path_in(view)),
                    mutation_in(&views),
                )
            });
            (who.as_str(), found)
        })
        .collect();
    let read_instead = "read them with `b10x-gates api --method GET`";
    for (who, found) in &judged {
        if let Some((Some(path), _)) = found {
            return Some(format!(
                "{who} carries the protection path {}; {OWNERS}; {read_instead}",
                shown(path)
            ));
        }
    }
    for (who, found) in &judged {
        if let Some((_, Some(name))) = found {
            return Some(format!(
                "{who} names the GraphQL mutation {name}; {OWNERS}; {read_instead}"
            ));
        }
    }
    if let Some((who, _)) = judged.iter().find(|(_, found)| found.is_none()) {
        return Some(format!(
            "{who} cannot be decoded: it is still changing after {MOST_DECODINGS} \
             percent-decodings, so it cannot be shown to leave rulesets and branch protection \
             alone; {OWNERS}"
        ));
    }
    if let Some(refusal) = uncheckable {
        return Some(refusal);
    }
    for check in [placeholder, body_encoding] {
        for (i, text) in args.iter().enumerate() {
            if let Some(found) = check(text) {
                return Some(format!("{} {found}; {OWNERS}", argument(i)));
            }
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

/// Headers that make GitHub decode the body before it reads it, lowercased, as a `gh`
/// `-H`/`--header` value spells them once white space is removed.
const BODY_ENCODINGS: [(&str, &str); 2] = [
    ("content-encoding:", "Content-Encoding"),
    ("transfer-encoding:", "Transfer-Encoding"),
];

/// An argument that holds a body-encoding header text, as the clause of a refusal. The
/// guard reads the bytes `gh` sends; with such a header GitHub may read them decoded (gzip,
/// for one), which the guard never sees. Read in every argument, not only after `-H`, so
/// no spelling of the flag (`-H v`, `-Hv`, `-H=v`, `-iH v`, `--header v`, `--header=v`)
/// and no value another flag consumes is missed; an argument that only mentions the
/// header, such as a comment body, is refused too (round 2, A3).
fn body_encoding(argument: &str) -> Option<String> {
    let squeezed: String = argument
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();
    BODY_ENCODINGS
        .iter()
        .find(|(spelled, _)| squeezed.contains(spelled))
        .map(|(_, name)| {
            format!(
                "holds the header text `{name}:`; as a header it may make GitHub decode the \
                 body before it reads it, so the bytes the guard reads would not be the request"
            )
        })
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

/// Most bytes of fillings one argument's placeholders are judged through, each filling
/// read whole: 4 MiB, enough for one placeholder in the longest argument Linux passes
/// (128 KiB) and for four in an endpoint of 400 bytes. More is refused as not judged
/// (round 3, B1).
const MOST_PLACEHOLDER_WORK: usize = 4 << 20;

/// Whether an argument sets the GraphQL `query` field: the key `query`, in any letter
/// case, before the first `=` of a field argument: `query=…` (the value of a separate
/// `-F`, `-f`, `--field` or `--raw-field`), `-Fquery=…`, `-fquery=…`, `-F=query=…`, a short
/// cluster such as `-iFquery=…`, `--field=query=…` and `--raw-field=query=…`.
fn sets_query_field(argument: &str) -> bool {
    let pair = if let Some(rest) = argument
        .strip_prefix("--field=")
        .or_else(|| argument.strip_prefix("--raw-field="))
    {
        rest
    } else if let Some(cluster) = argument.strip_prefix('-').filter(|c| !c.starts_with('-')) {
        // The first short flag that takes a value; only `-F` and `-f` take a field.
        match cluster.char_indices().find(|(_, c)| "fFHXqtp".contains(*c)) {
            Some((at, 'f' | 'F')) => {
                let rest = &cluster[at + 1..];
                rest.strip_prefix('=').unwrap_or(rest)
            }
            _ => return false,
        }
    } else {
        argument
    };
    pair.split_once('=')
        .is_some_and(|(key, _)| key.trim().eq_ignore_ascii_case("query"))
}

/// An argument whose placeholders `gh` could fill into a protection path or a mutation
/// name, as the clause of a refusal. Refused: a placeholder in an argument that sets the
/// GraphQL `query` field (`sets_query_field`); `{branch}` anywhere but as a whole field
/// value (`head={branch}`), since the branch name may hold `/`; and an argument that, read
/// as the endpoint, is a protection path for some owner or name, each segment holding one
/// tried as every `STAND_INS`. A field value `<key>=<placeholder>` is admitted: its first
/// segment starts with `<key>=`, which no fixed segment does.
fn placeholder(argument: &str) -> Option<String> {
    let text = argument.to_lowercase();
    if !PLACEHOLDERS.iter().any(|p| text.contains(p)) {
        return None;
    }
    if sets_query_field(argument) {
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
    let fillings = STAND_INS.len().pow(count);
    if fillings.saturating_mul(text.len()) > MOST_PLACEHOLDER_WORK {
        return Some(format!(
            "holds placeholders in more text than the guard can judge: {fillings} fillings \
             of {} bytes",
            text.len()
        ));
    }
    for n in 0..fillings {
        let mut filled = segments.clone();
        let mut rest = n;
        for &hole in &holes {
            filled[hole] = STAND_INS[rest % STAND_INS.len()];
            rest /= STAND_INS.len();
        }
        if let Some(path) = protection_named(&filled.join("/")) {
            return Some(format!(
                "becomes a protection path once gh fills its placeholders (as {})",
                shown(&path)
            ));
        }
    }
    None
}

/// The first of `MUTATIONS` the views of a text name, each as a whole GraphQL name: no
/// `[A-Za-z0-9_]` right before or after it, so `UpdateBranchProtectionRuleInput` names
/// none. In any letter case: the views are lowercased.
fn mutation_in(views: &[String]) -> Option<&'static str> {
    let word = |c: char| c.is_ascii_alphanumeric() || c == '_';
    MUTATIONS.into_iter().find(|name| {
        let name = name.to_lowercase();
        views.iter().any(|view| {
            view.match_indices(&name).any(|(at, _)| {
                !view[..at].chars().next_back().is_some_and(word)
                    && !view[at + name.len()..].chars().next().is_some_and(word)
            })
        })
    })
}

/// The bytes read as UTF-8 and as UTF-16 and UTF-32 in both byte orders (a JSON body may
/// arrive in any of them), each with JSON's string escapes undone and as given, each of
/// those percent-decoded until stable (an escape that does not decode stays as it is), all
/// lowercased. Bytes that do not decode become U+FFFD. `None` when a text is still changing
/// after `MOST_DECODINGS` decodings.
fn views(bytes: &[u8]) -> Option<Vec<String>> {
    let utf16 = |unit: fn([u8; 2]) -> u16| {
        char::decode_utf16(bytes.as_chunks::<2>().0.iter().map(|pair| unit(*pair)))
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect::<String>()
    };
    let utf32 = |unit: fn([u8; 4]) -> u32| {
        bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|four| char::from_u32(unit(*four)).unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect::<String>()
    };
    let mut views = Vec::new();
    for text in [
        String::from_utf8_lossy(bytes).into_owned(),
        utf16(u16::from_le_bytes),
        utf16(u16::from_be_bytes),
        utf32(u32::from_le_bytes),
        utf32(u32::from_be_bytes),
    ] {
        let unescaped = json_unescaped(&text);
        for start in [unescaped, text] {
            for stage in stages(&start, false)? {
                views.push(stage.to_lowercase());
            }
        }
    }
    views.dedup();
    Some(views)
}

/// The first protection path in a lowercased view, as a refusal shows it
/// (`protection_named`). A path may begin wherever `repos`, `repositories`, `orgs` or
/// `organizations` begins outside a longer word, and runs to the next white space, quote,
/// backtick or angle bracket. It runs on past a `\`, which every reading takes as a
/// separator, so `repos\o\r\rulesets` is found; what a refusal shows of it stops at the
/// protection segment (`protection_prefix`). Every place in one token is judged at once
/// (`protected_starts`), so time and memory stay linear in the view; only the first place
/// found is read again, as `protection_named` reads it, to show it (round 3, B1).
fn path_in(view: &str) -> Option<String> {
    let terminator = |c: char| c.is_whitespace() || "\"'`<>".contains(c);
    let mut begin = 0;
    let mut starts = Vec::new();
    let mut previous: Option<char> = None;
    for (at, c) in view
        .char_indices()
        .chain(std::iter::once((view.len(), ' ')))
    {
        if terminator(c) {
            if !starts.is_empty() {
                let token = &view[begin..at];
                let starts: Vec<usize> = starts.drain(..).map(|start| start - begin).collect();
                for (start, flagged) in starts.iter().zip(protected_starts(token, &starts)) {
                    if flagged
                        && let Some(path) = protection_named(&format!("/{}", &token[*start..]))
                    {
                        return Some(path);
                    }
                }
            }
            begin = at + c.len_utf8();
        } else if !previous.is_some_and(|p| p.is_alphanumeric())
            && (view[at..].starts_with("repos") || view[at..].starts_with("org"))
        {
            starts.push(at);
        }
        previous = Some(c);
    }
    None
}

/// For each of `starts` (ascending offsets in `token`, each where `repos` or `org` begins),
/// whether `protection_named` finds a protection path in `/` and the rest of the token, all
/// judged together in time linear in the token: each decoding of the token is folded once
/// and read once with its query cut and once without (`judge_line`). A start is never left
/// out where `protection_named` finds a path. A token still changing after
/// `MOST_DECODINGS` decodings, which no view holds, leaves every start to `path_in`.
fn protected_starts(token: &str, starts: &[usize]) -> Vec<bool> {
    let mut found = vec![false; starts.len()];
    let mut text = token.to_owned();
    let mut marks = starts.to_vec();
    for _ in 0..=MOST_DECODINGS {
        let (folded, at) = folded_marked(&text, &marks);
        for cut in [true, false] {
            judge_line(&folded, &at, cut, &mut found);
        }
        let (next, moved) = decoded_marked(&text, &marks);
        if next == text {
            return found;
        }
        text = next;
        marks = moved;
    }
    vec![true; starts.len()]
}

/// Marks each start whose window of a folded `text`, to its end or with `cut` to the next
/// `?` or `#`, reads as a protection path with its dot segments kept or resolved. With
/// `cut`, each run between `?` and `#` is read on its own (`judge_region`).
fn judge_line(text: &str, starts: &[usize], cut: bool, found: &mut [bool]) {
    let mut region = 0;
    let mut first = 0;
    while first < starts.len() {
        let end = if cut {
            text[region..]
                .find(['?', '#'])
                .map_or(text.len(), |at| region + at)
        } else {
            text.len()
        };
        let last = first + starts[first..].iter().take_while(|s| **s < end).count();
        if last > first {
            judge_region(
                &text[region..end],
                region,
                &starts[first..last],
                &mut found[first..last],
            );
        }
        first = last;
        region = end + 1;
    }
}

/// Marks each start (an offset in the whole text, `offset` before `region`) whose window,
/// from the start to the end of `region`, is a protection path. The region's segments are
/// read once: split at `/` and `\`, empty ones dropped, trimmed. A window reads the same
/// segments from the one holding its start, that one cut where the start is. With dot
/// segments resolved, a window keeps exactly the segments that survive resolution over the
/// whole region from its first segment on: a `..` removes the nearest surviving segment
/// before it, the same one whichever segment the reading began at, if that one lies in
/// the window.
fn judge_region(region: &str, offset: usize, starts: &[usize], found: &mut [bool]) {
    let mut spans = Vec::new();
    let mut begin = 0;
    for (at, c) in region
        .char_indices()
        .chain(std::iter::once((region.len(), '/')))
    {
        if c == '/' || c == '\\' {
            if at > begin {
                spans.push((begin, at));
            }
            begin = at + 1;
        }
    }
    let texts: Vec<&str> = spans.iter().map(|&(b, e)| region[b..e].trim()).collect();
    let count = texts.len();
    // The first `protection` segment at or after each index, kept and resolved.
    let mut kept_protection = vec![count; count + 1];
    for i in (0..count).rev() {
        kept_protection[i] = if fixed(texts[i], "protection") {
            i
        } else {
            kept_protection[i + 1]
        };
    }
    let mut survivors: Vec<usize> = Vec::new();
    for (i, text) in texts.iter().enumerate() {
        match *text {
            "." => {}
            ".." => {
                survivors.pop();
            }
            _ => survivors.push(i),
        }
    }
    let surviving = survivors.len();
    let mut first_survivor = vec![surviving; count + 1];
    let mut at = surviving;
    for i in (0..count).rev() {
        if at > 0 && survivors[at - 1] == i {
            at -= 1;
        }
        first_survivor[i] = at;
    }
    let mut resolved_protection = vec![surviving; surviving + 1];
    for i in (0..surviving).rev() {
        resolved_protection[i] = if fixed(texts[survivors[i]], "protection") {
            i
        } else {
            resolved_protection[i + 1]
        };
    }
    let mut segment = 0;
    for (start, flag) in starts.iter().zip(found.iter_mut()) {
        let start = start - offset;
        while spans[segment].1 <= start {
            segment += 1;
        }
        // Untrimmed: it begins with a letter, and `fixed` reads trailing white space as
        // trimming would.
        let first = &region[start..spans[segment].1];
        let kept = is_protection(
            count - segment,
            |i| if i == 0 { first } else { texts[segment + i] },
            |i| kept_protection[(segment + i).min(count)] < count,
        );
        let at = first_survivor[segment];
        let resolved = at < surviving
            && is_protection(
                surviving - at,
                |i| {
                    if i == 0 && survivors[at] == segment {
                        first
                    } else {
                        texts[survivors[at + i]]
                    }
                },
                |i| resolved_protection[(at + i).min(surviving)] < surviving,
            );
        *flag |= kept || resolved;
    }
}

/// `protection_prefix(reading).is_some()` for a reading of `len` segments given by
/// `segment`, with `protection_from(i)` telling whether a `protection` segment lies at or
/// after index `i`: the same decision, in constant time when both answer in constant time.
fn is_protection<'a>(
    len: usize,
    segment: impl Fn(usize) -> &'a str,
    protection_from: impl Fn(usize) -> bool,
) -> bool {
    if len == 0 {
        return false;
    }
    let first = segment(0);
    let (rest, organization) = if fixed(first, "repos") && len > 3 {
        (3, false)
    } else if fixed(first, "repositories") && len > 2 {
        (2, false)
    } else if (fixed(first, "orgs") || fixed(first, "organizations")) && len > 2 {
        (2, true)
    } else {
        return false;
    };
    let head = segment(rest);
    fixed(head, "rulesets")
        || (!organization && fixed(head, "branches") && protection_from(rest + 2))
}

/// The protection target of the first reading of `path` that is a protection path, as a
/// refusal shows it (`protection_prefix`).
fn protection_named(path: &str) -> Option<String> {
    readings(path, false)?
        .iter()
        .find_map(|segments| protection_prefix(segments))
}

/// Every reading of a path a server on the way may make, each as its segments: as given
/// and after each percent-decoding until stable (`stages`); lowercased; tab and newline
/// removed (the URL parser drops them); `\` as a separator (the URL parser reads it as
/// `/`); without and with what follows `?` or `#`; empty segments dropped (repeated and
/// trailing separators); each segment trimmed; `.` and `..` segments kept and resolved.
/// `None` when the path cannot be decoded.
fn readings(path: &str, strict: bool) -> Option<Vec<Vec<String>>> {
    let mut readings = Vec::new();
    for stage in stages(path, strict)? {
        let text: String = stage
            .chars()
            .filter(|c| !matches!(c, '\t' | '\n' | '\r'))
            .collect::<String>()
            .to_lowercase();
        let cut = text.split(['?', '#']).next().unwrap_or_default();
        for candidate in [cut, text.as_str()] {
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

/// A path's segments name a protection surface (`protection_prefix`).
fn protected(segments: &[String]) -> bool {
    protection_prefix(segments).is_some()
}

/// The protection surface a path's segments name, as a refusal shows it, or `None`:
/// `repos/<o>/<r>` or `repositories/<id>` followed by `rulesets`, or by
/// `branches/<branch...>/protection` with anything below; or `orgs/<o>` or
/// `organizations/<id>` followed by `rulesets`. Shown only up to and including `rulesets`
/// and a numeric ruleset id after it, or `protection`, each fixed segment in its plain
/// spelling, so nothing after the surface, and nothing a suffix such as `.json` holds,
/// reaches a refusal (round 2, A5).
fn protection_prefix(segments: &[String]) -> Option<String> {
    let first = segments.first()?;
    let (mut shown, rest): (Vec<&str>, &[String]) = if fixed(first, "repos") && segments.len() > 3 {
        (vec!["repos", &segments[1], &segments[2]], &segments[3..])
    } else if fixed(first, "repositories") && segments.len() > 2 {
        (vec!["repositories", &segments[1]], &segments[2..])
    } else if (fixed(first, "orgs") || fixed(first, "organizations")) && segments.len() > 2 {
        let family = if fixed(first, "orgs") {
            "orgs"
        } else {
            "organizations"
        };
        (vec![family, &segments[1]], &segments[2..])
    } else {
        return None;
    };
    let organization = shown[0].starts_with("org");
    if fixed(&rest[0], "rulesets") {
        shown.push("rulesets");
        if let Some(id) = rest
            .get(1)
            .filter(|id| !id.is_empty() && id.bytes().all(|b| b.is_ascii_digit()))
        {
            shown.push(id);
        }
    } else if !organization && fixed(&rest[0], "branches") {
        // A branch name may hold `/`, so `protection` anywhere after its first segment
        // counts.
        let at = rest.iter().skip(2).position(|s| fixed(s, "protection"))? + 2;
        shown.push("branches");
        shown.extend(rest[1..at].iter().map(String::as_str));
        shown.push("protection");
    } else {
        return None;
    }
    Some(format!("/{}", shown.join("/")))
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

/// The text and each percent-decoding of it until stable, at most `MOST_DECODINGS` of
/// them; `None` when the text is still changing after the last (round 2, A7). With
/// `strict`, the first decoding fails on a `%` that is not an escape or on bytes that are
/// not UTF-8. Every later decoding is lenient, such a `%` staying and invalid bytes
/// becoming U+FFFD: a `%` the first decoding yields is text, as in a label named `50%`
/// spelled `50%25` (round 2, A4).
fn stages(text: &str, strict: bool) -> Option<Vec<String>> {
    let mut stages = vec![text.to_owned()];
    loop {
        let last = stages.last().expect("one stage");
        let next = decoded(last, strict && stages.len() == 1)?;
        if next == *last {
            return Some(stages);
        }
        if stages.len() > MOST_DECODINGS {
            return None;
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
            match escape(bytes, i) {
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

/// The byte a `%` at `at` escapes: two hex digits exactly, since `from_str_radix` alone
/// would take `%+1`.
fn escape(bytes: &[u8], at: usize) -> Option<u8> {
    bytes
        .get(at + 1..at + 3)
        .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
        .and_then(|h| std::str::from_utf8(h).ok())
        .and_then(|h| u8::from_str_radix(h, 16).ok())
}

/// `decoded(text, false)` with each offset in `marks` (ascending, each at a character that
/// no escape holds) moved to where its character lands, through the lossy conversion too.
fn decoded_marked(text: &str, marks: &[usize]) -> (String, Vec<usize>) {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut moved = Vec::with_capacity(marks.len());
    let mut i = 0;
    while i < bytes.len() {
        while moved.len() < marks.len() && marks[moved.len()] <= i {
            moved.push(out.len());
        }
        if bytes[i] == b'%'
            && let Some(byte) = escape(bytes, i)
        {
            out.push(byte);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    moved.resize(marks.len(), out.len());
    // `String::from_utf8_lossy`, chunk by chunk, moving each mark with its byte.
    let mut string = String::with_capacity(out.len());
    let mut raw = 0;
    let mut mark = 0;
    for chunk in out.utf8_chunks() {
        let valid = chunk.valid();
        while mark < moved.len() && moved[mark] < raw + valid.len() {
            moved[mark] = string.len() + moved[mark].saturating_sub(raw);
            mark += 1;
        }
        string.push_str(valid);
        raw += valid.len();
        if !chunk.invalid().is_empty() {
            string.push(char::REPLACEMENT_CHARACTER);
            raw += chunk.invalid().len();
        }
    }
    for at in &mut moved[mark..] {
        *at = string.len();
    }
    (string, moved)
}

/// The fold every reading makes, `\t`, `\n` and `\r` removed then lowercased, with each
/// offset in `marks` (ascending, each at a character that is kept) moved to where its
/// character lands. Lowercasing changes lengths character by character; `Σ`, the one
/// letter whose lowercase depends on its neighbours, is two bytes either way.
fn folded_marked(text: &str, marks: &[usize]) -> (String, Vec<usize>) {
    let mut filtered = String::with_capacity(text.len());
    let mut moved = Vec::with_capacity(marks.len());
    for (at, c) in text.char_indices() {
        while moved.len() < marks.len() && marks[moved.len()] <= at {
            moved.push(filtered.len());
        }
        if !matches!(c, '\t' | '\n' | '\r') {
            filtered.push(c);
        }
    }
    moved.resize(marks.len(), filtered.len());
    let mut lowered = 0;
    let mut mark = 0;
    for (at, c) in filtered.char_indices() {
        while mark < moved.len() && moved[mark] == at {
            moved[mark] = lowered;
            mark += 1;
        }
        lowered += c.to_lowercase().map(char::len_utf8).sum::<usize>();
    }
    for at in &mut moved[mark..] {
        *at = lowered;
    }
    (filtered.to_lowercase(), moved)
}

/// JSON's string escapes undone, left to right and anywhere in the text, as the server's
/// JSON parser reads them: `\uXXXX` (a surrogate pair as one character, a lone surrogate
/// as U+FFFD), `\n`, `\t`, `\r`, `\b`, `\f`, `\"`, `\\` and `\/`. Any other backslash stays.
/// A mutation name is judged as a whole name, so the newline that a multi-line query
/// spells `\n` before it must read as a newline, not as the letter `n` (round 2, A1).
/// `\/` changes no verdict, since every path reading takes `\` as a separator; it is undone
/// so this view is the text the server reads.
fn json_unescaped(text: &str) -> String {
    let hex = |text: &str| {
        text.get(..4)
            .filter(|h| h.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|h| u32::from_str_radix(h, 16).ok())
    };
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find('\\') {
        out.push_str(&rest[..at]);
        let escape = &rest[at + 1..];
        let short = match escape.chars().next() {
            Some('n') => Some('\n'),
            Some('t') => Some('\t'),
            Some('r') => Some('\r'),
            Some('b') => Some(char::from(8u8)),
            Some('f') => Some(char::from(12u8)),
            Some(c @ ('"' | '\\' | '/')) => Some(c),
            _ => None,
        };
        if let Some(c) = short {
            out.push(c);
            rest = &escape[1..];
            continue;
        }
        let Some(unit) = escape.strip_prefix('u').and_then(hex) else {
            out.push('\\');
            rest = escape;
            continue;
        };
        // `u` and four digits; a high surrogate takes the low one after it, if any.
        let low = escape
            .get(5..)
            .and_then(|after| after.strip_prefix('\\'))
            .and_then(|after| after.strip_prefix('u'))
            .and_then(hex)
            .filter(|low| (0xD800..0xDC00).contains(&unit) && (0xDC00..0xE000).contains(low));
        match low {
            Some(low) => {
                let scalar = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                out.push(char::from_u32(scalar).unwrap_or(char::REPLACEMENT_CHARACTER));
                rest = &escape[11..];
            }
            None => {
                out.push(char::from_u32(unit).unwrap_or(char::REPLACEMENT_CHARACTER));
                rest = &escape[5..];
            }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The round 2 `path_in`, quadratic in its view: every place a path may begin is read
    /// again to the end of its token. The reference the linear `path_in` must agree with.
    fn path_in_reference(view: &str) -> Option<String> {
        let mut previous: Option<char> = None;
        for (at, c) in view.char_indices() {
            let rest = &view[at..];
            if !previous.is_some_and(|p| p.is_alphanumeric())
                && (rest.starts_with("repos") || rest.starts_with("org"))
            {
                let end = rest
                    .find(|c: char| c.is_whitespace() || "\"'`<>".contains(c))
                    .unwrap_or(rest.len());
                if let Some(path) = protection_named(&format!("/{}", &rest[..end])) {
                    return Some(path);
                }
            }
            previous = Some(c);
        }
        None
    }

    /// Pieces a text is built from: every fixed word and family, a name, an id, each
    /// separator, dot segments, a query and a fragment, suffixes a router strips, escapes
    /// that decode to a separator, a dot, a query, a `%` or a letter, white space, a quote.
    const PIECES: [&str; 34] = [
        "repos",
        "repositories",
        "orgs",
        "organizations",
        "rulesets",
        "branches",
        "protection",
        "main",
        "42",
        "x",
        "/",
        "/",
        "/",
        "\\",
        ".",
        "..",
        "?",
        "#",
        "-",
        ";",
        ".json",
        "%2f",
        "%5c",
        "%2e",
        "%3f",
        "%25",
        "%72",
        "%52",
        " ",
        "%20",
        "\t",
        "%09",
        "\"",
        "Repos",
    ];

    /// Texts from a fixed seed (xorshift), so a failing text is found again from its case.
    struct Texts(u64);

    impl Texts {
        fn next(&mut self) -> usize {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            usize::try_from(x % 1_000_003).expect("small")
        }

        fn pick<'a>(&mut self, from: &[&'a str]) -> &'a str {
            from[self.next() % from.len()]
        }

        /// Three texts in four are shaped like paths, so protection paths are common; the
        /// rest are pieces at random.
        fn text(&mut self) -> String {
            let mut text = String::new();
            if self.next().is_multiple_of(4) {
                for _ in 0..1 + self.next() % 16 {
                    text.push_str(self.pick(&PIECES));
                }
                return text;
            }
            for _ in 0..self.next() % 3 {
                text.push_str(self.pick(&PIECES));
            }
            text.push_str(self.pick(&FAMILIES));
            for _ in 0..self.next() % 9 {
                text.push_str(self.pick(&SEPARATORS));
                text.push_str(self.pick(&SEGMENTS));
            }
            for _ in 0..self.next() % 3 {
                text.push_str(self.pick(&PIECES));
            }
            text
        }
    }

    const FAMILIES: [&str; 9] = [
        "repos",
        "repos",
        "repositories",
        "orgs",
        "organizations",
        "x-repos",
        ".repos",
        "%72epos",
        "repos.json",
    ];

    const SEPARATORS: [&str; 7] = ["/", "/", "/", "\\", "//", "%2f", "/ "];

    const SEGMENTS: [&str; 22] = [
        "example",
        "main",
        "42",
        "rulesets",
        "rulesets",
        "branches",
        "branches",
        "protection",
        "protection",
        "rulesets.json",
        "protection;v",
        ".",
        "..",
        "..",
        "rulesets?x",
        "x#y",
        "?q",
        "%72ulesets",
        "%2e%2e",
        " rulesets",
        "repos",
        "\t",
    ];

    /// Texts each equivalence test reads.
    const CASES: usize = 120_000;

    /// Round 3, B1: the linear `path_in` finds the same first protection path, shown the
    /// same way, as the round 2 reference, over texts built to reach every rule.
    #[test]
    fn linear_path_finding_agrees_with_the_reference() {
        let mut texts = Texts(0x9E37_79B9_7F4A_7C15);
        let mut protected = 0;
        for case in 0..CASES {
            let text = texts.text();
            let found = path_in(&text);
            assert_eq!(found, path_in_reference(&text), "case {case}: {text:?}");
            protected += usize::from(found.is_some());
        }
        assert!(
            protected > 5_000,
            "the texts reach too few protection paths: {protected}"
        );
        eprintln!("{protected} of {CASES} texts carry a protection path");
    }

    /// Round 3, B1: the linear judgement marks exactly the starts at which the round 2
    /// reading finds a protection path, every start of every token, not only the first
    /// one `path_in` reads again.
    #[test]
    fn linear_judgement_marks_exactly_the_protected_starts() {
        let mut texts = Texts(0x2545_F491_4F6C_DD1D);
        let mut marked = 0;
        for case in 0..CASES {
            let text = texts.text();
            for token in text.split(|c: char| c.is_whitespace() || "\"'`<>".contains(c)) {
                let mut starts = Vec::new();
                let mut previous: Option<char> = None;
                for (at, c) in token.char_indices() {
                    if !previous.is_some_and(|p| p.is_alphanumeric())
                        && (token[at..].starts_with("repos") || token[at..].starts_with("org"))
                    {
                        starts.push(at);
                    }
                    previous = Some(c);
                }
                let expected: Vec<bool> = starts
                    .iter()
                    .map(|start| protection_named(&format!("/{}", &token[*start..])).is_some())
                    .collect();
                assert_eq!(
                    protected_starts(token, &starts),
                    expected,
                    "case {case}: {token:?} at {starts:?}"
                );
                marked += expected.iter().filter(|m| **m).count();
            }
        }
        assert!(marked > 5_000, "the texts mark too few starts: {marked}");
        eprintln!("{marked} starts marked over {CASES} texts");
    }
}
