---
format: aep.planning-md/3
id: review-result:hex-path-components-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: hex-encoded path components'
relations:
- reviews: story:hex-path-components
revision: 1
---
unit: 1
verdict: red
cases: executed 196→200, red 2
origin: introduced 2, pre-existing 0, undecided 0
wrote-outside-worktree: none
needs-coordinator: yes

These findings cover tree `gates-hex-unit1` at `7e2dccb`, with one untracked test file added. The decoded pass catches every spelling of a home root I tried. It fails in two other ways: it refuses relative ESS paths whose first segment is `home` or `Users`, and its cost grows quadratically with the number of home-path arrays in a file.

**1. What I touched.** `git diff --stat` is empty because the file is untracked. `git status --short` shows one line: `?? tests/adversary_hex_paths.rs` (280 lines). No source file changed. Format check and clippy (`--all-targets -D warnings`) both exit 0.

**2. Cases added** (`tests/adversary_hex_paths.rs`)

| Case | Asserts | Now |
|---|---|---|
| `adv_relative_ledger_path_whose_first_segment_is_home_is_admitted` | an ESS ledger path relative to the output root (`home/guide/intro.md`, `Users/models/user.ts`, `home/LICENSE`) is admitted; the same path as plain text is the control | red |
| `adv_decoded_pass_scales_linearly_with_the_number_of_arrays` | 8x the input costs less than 16x the time; plain-text paths and non-personal arrays are the controls | red |
| `adv_hex_root_spellings_are_refused` | refused: uppercase hex, CRLF with tabs and key/colon/bracket split across lines, marker renamed or first, double-escaped compact and pretty, odd-length element, not on line 1, plain path plus array on one line gives one finding | green |
| `adv_unrelated_components_keys_are_admitted` | admitted: OpenAPI `components` object, names made of hex digits, digests, `[]`, bare `/home` and `/Users` | green |

Red output, each case run alone first:
```
tests/adversary_hex_paths.rs:115:9:
assertion `left == right` failed: output-root-relative ledger path "home/guide/intro.md" refused as a home path
  left: [1]
 right: []
```
```
tests/adversary_hex_paths.rs:186:5:
superlinear decoded pass: 80000/10000 = 8x the input: plain line pass 109.922855ms -> 725.691988ms (6.6x); non-personal arrays 720.492408ms -> 6.107837282s (8.5x); personal arrays 1.03183209s -> 27.30756411s (26.5x)
```
The scaling case went through three versions. With 4x the input and a threshold of 8x, it was green on its first run and red (9.9x) on its second. With 8x the input and a threshold of 16x it was red alone (33.2x), green once inside the file, then red (23.3x). The load average on the machine was 18 to 25. Now the small input is timed five times and the fastest run kept, so contention can only raise the ratio. It has been red since.

**3. Suite run**, after the cases existed: `B10X_GATES_GITLEAKS=… cargo test --locked --no-fail-fast` exits 101. lib 2, main 0, adversary_artifact 2, adversary_hex_paths 2 passed and 2 failed (27.0x on this run), adversary_published_merge 9, artifact 9, published_merge 104, security 70 passed with 7 ignored, doc 0. The before count of 196 comes from a second run that names every other target and leaves out `adversary_hex_paths`; it exits 0.

**4. Findings** (base `9fd3fc5` has no decoder: 0 matches for `components` or `hex_paths` in its `src/scan.rs`)

- **`src/scan.rs:369` `path.push(b'/')` — false refusal. INFEASIBLE, introduced, warning.**
  - ESS uses the same shape for the absolute `root` and for every relative path in the ledger and transactions (`ess-cli/src/output_ownership/state.rs:57-90`, `from_relative` and `absolute`). Nothing in the array says which kind it is.
  - The contract always prepends `/`, so relative paths starting with `home/<x>/` or `Users/<x>/` are refused. The same text without a slash is admitted, which goes against the contract's own "`src/home/x` is not" rule.
  - What reaches it: nothing found. The only real `state.json` in the workspace (uilab) holds plain file names, and no directory named `home` or `Users` exists in any tree.
  - Possible fixes: decode only `payload.root`, or require a non-relative context. Either one gives up part of the "key need not be named" goal, so the story owner should decide.
- **`src/scan.rs:487` `paths.contains(&first)` — quadratic cost. CONFIRMED, introduced, warning.**
  - `paths` is a `Vec`, and every decoded finding adds one entry to it. `Matchers::text` at `:424` (`broken.contains`) has the same shape.
  - Measured in a debug build: 80k arrays take 30.3 s, against 5.7 s for the same arrays without home paths and 1.7 s for plain paths.
  - What reaches it: nothing found in practice. A file of up to 128 MiB can hold about 2M arrays, enough to hold the CI job until it times out. That is still a refusal, so no path gets through.
  - Fix: use a `HashSet<usize>` for `paths` (and a set for `text`).

**5. Attacked, could not break**
- The compact canonical ESS line (the real uilab file: 1161 bytes, 5 arrays), pretty-printed, CRLF, and JSON escaped once or twice: all refused on the key line.
- The inheritance rule needs every line the array spans; changing the start, end or span count made the unit's tests fail. Reusing lines from a previous version only reuses a name that was already there.
- Exceptions: the digest covers every spanned line. A compact array's digest equals its line's digest, as intended.
- Binary units, false refusals from digests or unrelated `"components"` keys, panics on spans or captures: none found.
- `NativePath` printed with `{:?}`, an unquoted spelling the regex would miss: ESS never prints it that way.
- Hex in the `service-sdk` planning store (`exact_bytes:"hex:…"`): 262 blobs, 1.25 MB decoded, 0 home paths.
- The odd-length-element and uppercase clauses had no test in the unit's suite; both are covered now and green.

**6. Written outside the worktree:** none. Scratch files are in `<tree>/target/scratch/adv/`: suite.log, before.log, fmt.log, clippy.log. The decoded planning-store copies were deleted.

```findings
- file: src/scan.rs
  line: 369
  category: acceptance
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: every components array is joined with a leading slash, so ESS output-root-relative ledger paths starting with home/<x>/ or Users/<x>/ are refused although their plain text is admitted; no such output tree was found in the workspace
- file: src/scan.rs
  line: 487
  category: property
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: the decoded pass looks every span up in a Vec that grows per finding (and text() at :424 likewise), so n personal arrays cost n^2/2 comparisons, measured 27x time for 8x input against 9x for both linear controls
```
