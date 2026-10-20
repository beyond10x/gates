---
format: aep.planning-md/3
id: review-result:protection-writes-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: protection write refusal'
relations:
- reviews: story:api-protection-writes
revision: 1
---
```
unit: story:api-protection-writes, tree ~/.local/state/worktree/trees/b10x/gates/gates-fix-protection-writes at bab833e plus one untracked test file
verdict: red (8 cases red; 7 findings: CONFIRMED 4, INFEASIBLE 3; no write admitted)
cases: executed 527→539, red 8
origin: introduced 7 / pre-existing 0 / undecided 0
wrote-outside-worktree: 3 paths
needs-coordinator: whether over-refusal the ESS states on purpose (findings 3, 4) counts as a break; whether a bounded-memory crash on a constructed input holds the unit (finding 7)
```

**1. Diff.** `git diff --stat` is empty because the only change is untracked: `?? tests/adversary_protection_writes.rs` (383 lines, a test file). No `src/` or other path touched.

**2. Cases added** in `tests/adversary_protection_writes.rs`, run alone first (exit 101, 4 passed, 8 failed):

| Case (line) | Now | Red output, isolated run |
|---|---|---|
| `graphql_introspection_of_a_mutation_input_type_reaches_the_token_step` :184 | red | `POST /graphql refused: the GraphQL request names the mutation updateBranchProtectionRule` |
| `gh_api_read_of_a_file_named_query_reaches_the_token_step` :196 | red | `gh api argument 2 fills a placeholder into a GraphQL query` |
| `gh_api_comment_mentioning_content_encoding_reaches_the_token_step` :205 | red | `gh api argument 4 sets a Content-Encoding header` |
| `api_write_to_a_label_with_an_encoded_percent_reaches_the_token_step` :218 | red | `PATCH /repos/example/example/labels/50%25 refused: the path cannot be decoded` |
| `refusal_does_not_echo_file_text_after_a_json_newline_escape` :228 | red | `carries the protection path /repos/example/example/rulesets\\nadversary-marker-text` |
| `gh_api_protection_path_after_an_encoding_header_is_named` :252 | red | `gh api argument 3 sets a Content-Encoding header` (the path is not named) |
| `nested_percent_encoding_in_an_api_path_is_judged_within_bounded_memory` :268 | red | `memory allocation of 47295 bytes failed`, the process aborted and dumped core |
| `nested_percent_encoding_in_an_input_file_is_judged_within_bounded_memory` :292 | red | `memory allocation of 258199 bytes failed`, the process aborted and dumped core |
| two control cases :280, :304 (same size, no nesting, same 512 MiB cap) | green | they rule out the cap itself as the cause |
| two no-panic sweeps over boundary inputs :319, :352 | green | |

After that first run I added `--core=0` to the cap so later runs write no core file. The assertions did not change. The second isolated run gave the same 8 red.

**3. Suite run.** `b10x-build-slot cargo test --locked --no-fail-fast` gave exit 101: 531 passed, 8 failed, 539 executed. The only failing target is `adversary_protection_writes`. `api_protection_writes` passed 96/96 and `security_protection_writes` 33/33. The "before" count, 527, is that same run with my file's 12 cases taken out. `cargo fmt --all --check` passes, and so does clippy on the new target with `-D warnings`.

**4. Findings.** Each holds against bab833e. `src/protection.rs` does not exist at 94b5d40, so all are `introduced`.

| # | Where | What was measured | What reaches it | Verdict, severity |
|---|---|---|---|---|
| 1 | src/protection.rs:303 | A GraphQL introspection read that names the type `UpdateBranchProtectionRuleInput` is refused. Matching is by substring in any case, so it breaks Acceptance "a query that names none of them is not" refused | real route; an agent reading the schema before handing a change to the owner; low to moderate | CONFIRMED, note |
| 2 | src/protection.rs:222 | Any argument that has a placeholder and contains the text `query` is refused, e.g. a read of `repos/{owner}/{repo}/contents/docs/query.md`. ESS :543 says "naming a GraphQL `query`" | real route; low | CONFIRMED, note |
| 3 | src/protection.rs:175 | An issue comment that mentions `Content-Encoding:` is refused. ESS :535 says "an argument that sets" the header; the code comment says matching every argument is deliberate | real route; low | CONFIRMED, note |
| 4 | src/protection.rs:468 | `PATCH .../labels/50%25` (a label named `50%`) is refused, because the guard decodes until stable and the second decoding fails. ESS :568 states "at any decoding", and the unit's own case `%25zz` locks this in; the story refuses only protection writes. Possible fix: judge later decodings leniently | real route; low | CONFIRMED, note |
| 5 | src/protection.rs:355 | The path pulled from a file runs on to the next space or quote, so after a JSON `\n` escape the refusal prints the next word of the file (up to 300 characters). This happens before the policy scan | real route; the request is refused either way and only the message text is affected | INFEASIBLE, note |
| 6 | src/protection.rs:69 vs ess/domains/delivery.yaml:560,573 | The ESS takes the first declared outcome whose guard holds, so `protection-path` (`ProtectionWrite`, naming the path) should win. The code checks arguments in order, so an earlier header argument yields the encoding refusal and never names `/repos/example/example/rulesets/42` | real route, but built: no real caller sends that header | INFEASIBLE, note |
| 7 | src/protection.rs:446 (also :335) | `stages` keeps every decoding, so memory grows with the square of the nesting depth. A 64 KiB path or 256 KiB file nested in `%25` aborts under a 512 MiB cap; without a cap, this machine could run out of memory | real route (`api --path`, `gh api --input`), but the input is built; no real caller nests `%25` | INFEASIBLE, warning |

**5. What I attacked and could not break.**
- No write admitted: every REST family, normalisation, mutation and gh file spelling named in the story's Acceptance is refused. I added no new tests for that direction beyond the unit's 129.
- No panic on an empty path, a `%` at the end, `%%`, a 100 KB path, invalid UTF-8 or UTF-16/32 bodies, flags with no value at the end, or multibyte clusters.
- `ess specify validate --path ess`: `gates v1 — 3 file(s), valid`.
- The unit's tests assert literal refusal text or reaching the token step; none has a shape that cannot fail.

**6. Paths written outside the worktree.**
- `~/.cache/gates-wave-ruleset-writes/adversary/scratch/adversary-alone.log`
- `~/.cache/gates-wave-ruleset-writes/adversary/scratch/adversary-alone-2.log`
- `~/.cache/gates-wave-ruleset-writes/adversary/scratch/suite.log`

The tests also create temporary directories under `~/.cache/claude-tmp`, removed on drop (0 left after the first run). The first run's two core files were written inside those directories and went with them.

```findings
- file: src/protection.rs
  line: 303
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: a GraphQL introspection read naming the type UpdateBranchProtectionRuleInput is refused, because mutation names are matched as case-insensitive substrings, against the acceptance that a query naming no mutation stays open
- file: src/protection.rs
  line: 222
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: any gh api argument holding a placeholder and the text "query" is refused, including a REST read of contents/docs/query.md, where the ESS says only an argument naming a GraphQL query
- file: src/protection.rs
  line: 175
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: a gh api comment body that mentions "Content-Encoding:" is refused although the ESS refuses only an argument that sets the header
- file: src/protection.rs
  line: 468
  category: acceptance
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: an unrelated write whose path holds a correctly encoded literal percent (labels/50%25) is refused, because decoding until stable fails on the second decoding
- file: src/protection.rs
  line: 355
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: a path found in a file runs to the next space or quote, so after a JSON newline escape the refusal prints file text beyond the path, before the policy scan
- file: ess/domains/delivery.yaml
  line: 560
  category: contract-drift
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: the ESS takes protection-path before body-encoding-header, but the code refuses on the first matching argument, so a protected path after an encoding header is refused without being named
- file: src/protection.rs
  line: 446
  category: boundary
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: stages keeps every percent decoding, so a 64 KiB path or 256 KiB input nested in %25 uses memory quadratic in its depth and aborts under a 512 MiB cap instead of being judged
```
