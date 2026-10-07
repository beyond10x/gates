---
format: aep.planning-md/3
id: review-result:hex-path-components-adversary-2
kind: review-result
status: active
title: 'Adversary pass 2: hex-encoded path components'
relations:
- reviews: story:hex-path-components
revision: 1
---
unit: 1
verdict: red
cases: executed 200→205, red 1
origin: introduced 1, pre-existing 1, undecided 0
wrote-outside-worktree: none
needs-coordinator: yes

Pass 2 covers `a9413a7` plus two untracked test files. Your fix holds, and the soft-wrap rewrites report the same lines, rules and digests as the old code. Two problems are open:
- **Memory (introduced, note):** `run` now holds 16 bytes per line of every unit.
- **Coverage (pre-existing, warning):** the suite you handed me cannot detect any soft-wrap regression. It still passes all 200 cases when `wrapped_lines` is stubbed to return nothing, so my new cases are the only thing checking your rewrite.

**1. What I touched.** `git status --short` shows only `?? tests/adversary_line_memory.rs` and `?? tests/adversary_wrapped_lines.rs`; `git diff --stat` is empty. No source file changed. Format check and clippy (`--all-targets -D warnings`) both exit 0.

**2. Cases added**

| Case | Asserts | Now |
|---|---|---|
| `adversary_line_memory.rs` `adv_run_memory_does_not_grow_with_the_number_of_lines` | 4 MiB of empty lines raises peak RSS by less than 4 KiB lines of the same size plus 16 MiB | red |
| `adversary_wrapped_lines.rs` `adv_wrapped_findings_keep_their_lines_rules_and_digests` | exact lines from both `run` and `text` for 13 inputs (one per edge below); each digest is over its own line; no line reported twice; binary units report nothing | green |
| `adv_wrapped_lines_match_the_old_attribution` | `wrapped_lines` equals the old count-from-the-start code on 1,500 generated units (fixed seed, 7,274 wrapped lines); `run` and `text` report the union of the line pass and the wrapped pass | green |
| `adv_wrapped_pass_scales_linearly_with_the_number_of_findings` | 8x the wrapped findings costs less than 16x the time | green |
| `adv_text_scales_linearly_with_decoded_and_wrapped_findings` | the same for `Matchers::text` | green |

Edges in the 13 inputs:
- a match at the very start or end of the unit, and a unit with no final newline
- CRLF, with the `\r` kept in the digest
- plain and wrapped matches on the same line (one finding) and on the next line (two)
- one occurrence split twice across three lines
- two patterns on different lines, overlapping, and one plain plus one wrapped on the same line
- a blockquote, capitals, and a literal too short to be wrapped

Red output, run alone:
```
thread 'adv_run_memory_does_not_grow_with_the_number_of_lines' (3963780) panicked at tests/adversary_line_memory.rs:81:5:
a 4 MiB unit of empty lines grew the peak resident set by 68 MiB; the same size in 4 KiB lines by 2 MiB
```

How the soft-wrap cases got to this state:
- Their first build failed on a `json!` macro error in my own file.
- After that fix all four were green.
- I then added two mutated attributions inside the property case (cursor carried from the match end; line of the match end). They disagree with the old code on 1,164 and 1,397 of the 1,500 units.
- Last, I cut the units from 4,000 to 1,500 (59 s to 27 s) and tightened the thresholds to the measured counts.

**3. Suite run** (after the cases): `cargo test --locked --no-fail-fast` exits 101.
- 205 executed, with 7 ignored in `security.rs`.
- The only failure is my memory case.
- With my two new files deselected, 200 pass with exit 0.

**4. Findings**
- **`src/scan.rs:492` — memory per line. CONFIRMED, introduced, note.**
  - `unit.bytes.split(..).collect()` builds a `Vec<&[u8]>` for every non-binary unit, whether or not the hex or soft-wrap pass finds anything. It was added in `7e2dccb` and moved in `a9413a7`; the base streamed the lines.
  - Measured: 68 MiB for a 4 MiB unit of empty lines, against 2 MiB for the same size in 4 KiB lines. 4,194,305 lines × 16 bytes = 64 MiB, which accounts for it.
  - What reaches it: no legitimate file found. Typical text averages 30–40 bytes per line, so about 0.5x. The worst case is adversarial: a 128 MiB unit of empty lines costs about 2 GiB.
  - Fix: build `lines` only when the hex or soft-wrap pass returns a hit.
- **`tests/security.rs:1188` — the soft-wrap pass has no running test. CONFIRMED, pre-existing, warning.**
  - `#[ignore = "DEFECT: line-based scanning…"]` is out of date: `a_literal_split_across_a_line_break_is_still_caught` passes when run with `--ignored`. It is the only test that splits a literal across lines.
  - Measured on a scratch copy with `wrapped_lines` stubbed to return nothing: the suite you handed me passes 200 of 200, exit 0. My four soft-wrap cases go red on the same copy (`left: []` against `right: [1]`, and `left: 0` against `right: 10000`).
  - A second scratch mutant, `lines.get(line)` (off by one), fails my digest check: `digest is not over line 1 of "synthetic-restr\nicted-identifier"`.
  - What reaches it: the `a9413a7` changes to `wrapped_lines`, the reported-line skip and the line lookup by index.
  - Fix: remove the `#[ignore]` (that edits an existing case, which is not mine to do), or keep my cases.

**5. Attacked, could not break**
- **Pass-1 scaling fix:** personal arrays now grow 0.71 s → 5.97 s (8.4x for 8x the input), down from 1.10 s → 36.6 s (33.2x).
- **`text` and the soft-wrap pass:** both linear at 10k and 80k findings.
- **Carried line count:** matches the old attribution on every edge in part 2 and on all 1,500 generated units.
- **Sets instead of lists:** `reported`, `paths` and `seen` give the same deduplication as before.
- **Your rewrite of my relative-array case:** it asserts refusal and passes. Not raised again.

**6. Written outside the worktree:** none. Scratch is inside the tree at `target/scratch/adv/`: logs, plus `mut/`, a mutated copy of the crate with its own `target/` (798 MiB). I left it in place because build directories are not mine to delete; `worktree finish --discard-cache` will remove it.

```findings
[
  {"file": "src/scan.rs", "line": 492, "category": "property", "severity": "note", "verdict": "CONFIRMED", "origin": "introduced", "message": "run collects every line of every non-binary unit into a Vec<&[u8]> before the hex and soft-wrap passes, 16 bytes per line: 68 MiB peak for a 4 MiB unit of empty lines against 2 MiB for the same size in 4 KiB lines; build it only when either pass returns a hit"},
  {"file": "tests/security.rs", "line": 1188, "category": "mutant", "severity": "warning", "verdict": "CONFIRMED", "origin": "pre-existing", "message": "the only test that splits a literal across lines is ignored as a defect it no longer has, so the handed suite passes 200 of 200 with wrapped_lines stubbed to return nothing and cannot detect a regression in the soft-wrap code a9413a7 rewrote"}
]
```
