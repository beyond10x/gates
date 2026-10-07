//! Adversary cases, pass 2 of `story:hex-path-components`: the soft-wrap pass that
//! `a9413a7` rewrote (line attribution carried forward, the reported-line skip, the
//! line lookup by index) must report exactly the lines, rules and digests the old
//! code did, and the decoded pass and `Matchers::text` must stay linear.
use b10x_gates::{
    digest,
    git::Unit,
    policy::{Policy, Repository},
    scan::{self, Matchers, SecretFinding, SecretScanner},
};
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

fn a() -> String {
    ["synthetic", "restricted", "identifier"].join("-")
}
fn b() -> String {
    ["restricted", "identifier", "plus"].join("-")
}

/// Two wrapped literals that overlap, and one too short to be wrapped.
fn policy() -> Policy {
    Policy {
        version: 1,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![a(), b(), "zqxw".into()],
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

fn line_of(text: &[u8], line: usize) -> &[u8] {
    text.split(|v| *v == b'\n').nth(line - 1).unwrap()
}

/// `private-identifiers` lines from `run`, after checking that no line is reported
/// twice and that every digest is over exactly the line the finding names.
fn run_lines(p: &Policy, text: &[u8]) -> Vec<usize> {
    let report = scan::run(p, REPOSITORY, &[unit(text)], &mut NoSecrets).unwrap();
    let mut lines = Vec::new();
    for f in report
        .findings
        .iter()
        .filter(|f| f.rule == "private-identifiers")
    {
        assert_eq!(
            f.content_sha256,
            digest(line_of(text, f.line)),
            "digest is not over line {} of {:?}",
            f.line,
            String::from_utf8_lossy(text)
        );
        lines.push(f.line);
    }
    let mut sorted = lines.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        lines.len(),
        "a line reported twice: {lines:?} in {:?}",
        String::from_utf8_lossy(text)
    );
    sorted
}

fn text_lines(m: &Matchers, text: &[u8]) -> Vec<usize> {
    m.text(text)
        .into_iter()
        .filter(|(_, r)| *r == "private-identifiers")
        .map(|(l, _)| l)
        .collect()
}

#[test]
fn adv_wrapped_findings_keep_their_lines_rules_and_digests() {
    let p = policy();
    let m = Matchers::build(&p).unwrap();
    let (a, b) = (a(), b());
    let cases: Vec<(String, Vec<usize>)> = vec![
        // At the very start of the unit, and the unit ends without a newline.
        (format!("{}\n{}", &a[..15], &a[15..]), vec![1]),
        // At the very end of the unit, without a final newline.
        (format!("a\nb\n{}\n{}", &a[..12], &a[12..]), vec![3]),
        // CRLF: the start line keeps its carriage return in the digest.
        (format!("x\r\n{}\r\n{}\r\n", &a[..10], &a[10..]), vec![2]),
        (format!("a\r\n{}\r\n{}", &a[..21], &a[21..]), vec![2]),
        // A wrapped literal starting on the line a plain one is on: one finding.
        (format!("{a} {}\n{}\n", &a[..14], &a[14..]), vec![1]),
        // ... and on the line after it: two.
        (format!("{a}\n{}\n{}\n", &a[..14], &a[14..]), vec![1, 2]),
        // Plain and wrapped interleaved, one occurrence split twice over three lines.
        (
            format!(
                "{a}\n{}\n{}\n{a}\n\n{}\n{}\n{}\n",
                &a[..5],
                &a[5..],
                &a[..9],
                &a[9..20],
                &a[20..]
            ),
            vec![1, 2, 4, 6],
        ),
        // Two patterns, wrapped on different lines.
        (
            format!(
                "x\n{}\n{}\n{}\n{}\n",
                &a[..25],
                &a[25..],
                &b[..22],
                &b[22..]
            ),
            vec![2, 4],
        ),
        // Two patterns overlapping, both starting on line 1.
        (format!("{}\n{}-plus\n", &a[..21], &a[21..]), vec![1]),
        // A plain match of one pattern and a wrapped match of the other, same line.
        (format!("{a}-\nplus\n"), vec![1]),
        // Quoted, and in capitals.
        (format!("> {}\n> {}\n", &a[..16], &a[16..]), vec![1]),
        (
            format!("{}\n{}\n", &a[..15], &a[15..]).to_uppercase(),
            vec![1],
        ),
        // The short literal is never wrapped.
        ("zq\nxw\nzqxw\n".into(), vec![3]),
    ];
    for (text, expected) in cases {
        assert_eq!(run_lines(&p, text.as_bytes()), expected, "run: {text:?}");
        assert_eq!(text_lines(&m, text.as_bytes()), expected, "text: {text:?}");
    }
    // A binary unit stays out of both passes.
    let binary = format!("\0{a}\n{}\n{}\n", &a[..14], &a[14..]);
    assert!(run_lines(&p, binary.as_bytes()).is_empty());
}

/// The pre-`a9413a7` attribution: every match recounted from the unit start.
fn wrapped_source(literal: &str) -> String {
    let mut out = String::new();
    for (i, ch) in literal.chars().enumerate() {
        if i > 0 {
            out.push_str(r"(?:-?[ \t]*\r?\n[ \t>|*#]*)?");
        }
        out.push_str(&regex::escape(&ch.to_string()));
    }
    out
}

fn old_wrapped_lines(patterns: &[regex::bytes::Regex], unit: &[u8]) -> Vec<usize> {
    let mut lines: Vec<usize> = patterns
        .iter()
        .flat_map(|w| w.find_iter(unit))
        .filter(|m| unit[m.start()..m.end()].contains(&b'\n'))
        .map(|m| unit.iter().take(m.start()).filter(|b| **b == b'\n').count() + 1)
        .collect();
    lines.sort_unstable();
    lines.dedup();
    lines
}

/// Two wrong carries the corpus must tell apart from the old attribution, so a
/// green comparison means something: the cursor moved to the match end (newlines
/// inside a match never counted), and the line a match ends on.
fn mutant_wrapped_lines(
    patterns: &[regex::bytes::Regex],
    unit: &[u8],
    from_end: bool,
) -> Vec<usize> {
    let mut lines = Vec::new();
    for w in patterns {
        let (mut cursor, mut line) = (0, 1);
        for m in w.find_iter(unit) {
            if !unit[m.start()..m.end()].contains(&b'\n') {
                continue;
            }
            if from_end {
                line += unit[cursor..m.start()]
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count();
                cursor = m.end();
                lines.push(line);
            } else {
                line += unit[cursor..m.end()]
                    .iter()
                    .filter(|b| **b == b'\n')
                    .count();
                cursor = m.end();
                lines.push(line);
            }
        }
    }
    lines.sort_unstable();
    lines.dedup();
    lines
}

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// Fixed seed. Units built from literal fragments, whole literals and every kind
/// of break the wrapped pattern admits or refuses, compared with the old code.
#[test]
fn adv_wrapped_lines_match_the_old_attribution() {
    let p = policy();
    let m = Matchers::build(&p).unwrap();
    let patterns: Vec<regex::bytes::Regex> = p
        .forbidden_literals
        .iter()
        .filter(|v| v.chars().count() >= 8)
        .map(|v| {
            regex::bytes::RegexBuilder::new(&wrapped_source(v))
                .case_insensitive(true)
                .size_limit(1 << 20)
                .build()
                .unwrap()
        })
        .collect();
    let literals = [a(), b()];
    let breaks = [
        "\n", "\r\n", "-\n", " \n ", "\n> ", "\n| ", "\n\n", "\t\r\n# ",
    ];
    let filler = [
        "x",
        " ",
        "\n",
        "\r\n",
        "",
        "synthetic",
        "identifier",
        "-plus",
    ];
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let (mut wrapped, mut caught_end_cursor, mut caught_end_line) = (0, 0, 0);
    for _ in 0..1500 {
        let mut text = String::new();
        for _ in 0..1 + rng.below(24) {
            match rng.below(4) {
                0 => text.push_str(filler[rng.below(filler.len())]),
                1 => text.push_str(&literals[rng.below(2)]),
                _ => {
                    let l = &literals[rng.below(2)];
                    let mut cuts: Vec<usize> = (0..1 + rng.below(3))
                        .map(|_| 1 + rng.below(l.len() - 1))
                        .collect();
                    cuts.sort_unstable();
                    cuts.dedup();
                    let mut from = 0;
                    for cut in cuts {
                        text.push_str(&l[from..cut]);
                        text.push_str(breaks[rng.below(breaks.len())]);
                        from = cut;
                    }
                    text.push_str(&l[from..]);
                }
            }
        }
        let bytes = text.as_bytes();
        let old = old_wrapped_lines(&patterns, bytes);
        wrapped += old.len();
        caught_end_cursor += usize::from(mutant_wrapped_lines(&patterns, bytes, true) != old);
        caught_end_line += usize::from(mutant_wrapped_lines(&patterns, bytes, false) != old);
        assert_eq!(m.wrapped_lines(bytes), old, "{text:?}");
        // `run` reports the union of the line pass and the wrapped lines, once each,
        // with each digest over its own line (checked inside `run_lines`).
        let plain: Vec<usize> = bytes
            .split(|v| *v == b'\n')
            .enumerate()
            .filter(|(_, l)| {
                let l = String::from_utf8_lossy(l).to_lowercase();
                p.forbidden_literals.iter().any(|v| l.contains(v.as_str()))
            })
            .map(|(i, _)| i + 1)
            .collect();
        let mut union: Vec<usize> = plain.iter().chain(&old).copied().collect();
        union.sort_unstable();
        union.dedup();
        assert_eq!(run_lines(&p, bytes), union, "run: {text:?}");
        assert_eq!(text_lines(&m, bytes), union, "text: {text:?}");
    }
    eprintln!("wrapped {wrapped}, mutants caught {caught_end_cursor} and {caught_end_line}");
    assert!(
        wrapped > 4000,
        "the generator produced {wrapped} wrapped lines"
    );
    assert!(
        caught_end_cursor > 500 && caught_end_line > 500,
        "the corpus cannot tell a wrong carry from the old attribution: \
         {caught_end_cursor} and {caught_end_line} units disagree"
    );
}

fn fastest_of_five(f: impl Fn() -> Duration) -> Duration {
    (0..5).map(|_| f()).min().unwrap()
}

fn ratio(a: Duration, b: Duration) -> f64 {
    b.as_secs_f64() / a.as_secs_f64().max(1e-9)
}

/// The old soft-wrap pass recounted newlines from the unit start for every match
/// and looked each finding's line up by splitting from the start again.
#[test]
fn adv_wrapped_pass_scales_linearly_with_the_number_of_findings() {
    let p = policy();
    let a = a();
    let pair = format!("{}\n{}\n", &a[..14], &a[14..]);
    let (small, large) = (10_000, 80_000);
    let time = |n: usize| {
        let u = unit(pair.repeat(n));
        let start = Instant::now();
        let report = scan::run(&p, REPOSITORY, &[u], &mut NoSecrets).unwrap();
        let elapsed = start.elapsed();
        assert_eq!(report.results["private-identifiers"].findings, n);
        elapsed
    };
    let (s, l) = (fastest_of_five(|| time(small)), time(large));
    assert!(
        ratio(s, l) < 16.0,
        "8x the wrapped findings took {:.1}x the time ({s:?} -> {l:?})",
        ratio(s, l)
    );
}

/// `Matchers::text` serves `scan-text`, `gh --` and `api --input`.
#[test]
fn adv_text_scales_linearly_with_decoded_and_wrapped_findings() {
    let p = policy();
    let m = Matchers::build(&p).unwrap();
    let a = a();
    let components: Vec<String> = ["home", "fixture-person", "work"]
        .iter()
        .map(hex::encode)
        .collect();
    let array = format!(
        "{}\n",
        serde_json::to_string(&serde_json::json!({ "components": components })).unwrap()
    );
    let pair = format!("{}\n{}\n", &a[..14], &a[14..]);
    for (name, text) in [("decoded", array), ("wrapped", pair)] {
        let (small, large) = (10_000, 80_000);
        let time = |n: usize| {
            let bytes = text.repeat(n);
            let start = Instant::now();
            let broken = m.text(bytes.as_bytes());
            let elapsed = start.elapsed();
            assert_eq!(broken.len(), n, "{name}");
            elapsed
        };
        let (s, l) = (fastest_of_five(|| time(small)), time(large));
        assert!(
            ratio(s, l) < 16.0,
            "{name}: 8x the findings took {:.1}x the time ({s:?} -> {l:?})",
            ratio(s, l)
        );
    }
}
