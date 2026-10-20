---
format: aep.planning-md/3
id: review-result:protection-writes-security-1-verbatim
kind: review-result
status: active
title: 'Security review 1 (conformance retry): protection write refusal'
relations:
- reviews: story:api-protection-writes
revision: 1
---
```
unit: story:api-protection-writes, at 921f617 plus the uncommitted tests/security_protection_writes.rs
verdict: green
cases: executed 487→520, red 0
origin: introduced 4, pre-existing 0, undecided 0
wrote-outside-worktree: 3 logs in ~/.cache/gates-wave-ruleset-writes/review/scratch; temporary test sandboxes under $TMPDIR, deleted when each test ends
needs-coordinator: no
```

All 33 brief rows conform. None of the 4 findings is a guard gap the brief's rows reach: one is a test that doesn't check what its name says, and three are judgement items whose reachability is unproven.

**1. Diff.** `git --no-pager diff --stat` is empty (exit 0). `git status --short` shows only `?? tests/security_protection_writes.rs`. Nothing under `src/` changed.

**2. Cases** in `tests/security_protection_writes.rs`, run alone (log `security-2-alone-2.log`): `test result: ok. 33 passed; 0 failed`, exit 0.

| group | rows | now |
|---|---|---|
| `api` REST refused | 13 | green |
| `api` GraphQL refused | 4 | green |
| `api` reaches token step | 5 | green |
| `gh -- api` refused | 9 | green |
| `gh -- api` reaches token step | 2 | green |

- **First run:** 2 red, both from my own fixture checks (log `security-2-alone.log`). The file-writing tool had turned the escapes `\u0064` and `\u0063` into the plain letters `d` and `c`. The fixtures now build the escape at run time, so the reds were not findings.
- **Skipped as already asserted with the same input:**
  - HEAD `/repos/example/example/branches/main/protection` (`tests/api_protection_writes.rs:179`)
  - gh `graphql -F query=@-` and `graphql --input -` (`tests/api_protection_writes.rs:427-436`)
- **Brief vs contract:** the brief expected gh `api repos/example/example/rulesets` to reach `gh`. The story, the `BotApi` outcome `protection-path` and the `gh_api_refusal` doc all refuse a protection path through `gh -- api` whatever the method. I asserted refused; it is green.
- **`-f query=@file`:** asserted admitted. `-f` sends the text `@file` literally, never the file's contents, so admitting it is correct.

**3. Suite**, run after the cases existed: `cargo test --locked --no-fail-fast`, exit 0, 520 executed, 6 ignored (log `security-2-suite.log`). The before count, 487, is 520 minus the 33 in my file from that same run.

**4. Findings, at 921f617**

| # | file:line | verdict | origin | what was measured / what reaches it |
|---|---|---|---|---|
| F1 | tests/api_protection_writes.rs:283 | CONFIRMED | introduced | `graphql_mutation_behind_a_json_escape_is_refused` has no `\u` escape in its body, and no other test in that file has one. If the `\u` handling in `json_unescaped` were removed, the unit's suite would stay green; I checked this by reading the code, not by running a mutant. My two escape cases cover it now. Likely cause: the same tool decoding I hit. Fix: build the escape at run time. |
| F2 | src/main.rs:287 | INFEASIBLE | introduced | Judgement 2: the guard reads the `--input` / `@file` file once, and `gh` reads it again after the token is minted (`src/delivery.rs:361`). Neither the guard nor the README covers that gap. Only a caller rewriting its own file in that window can exploit it, and the story's Non-goals already concede such a caller (it holds the App key). |
| F3 | src/protection.rs:63 | INFEASIBLE | introduced | Judgement 1: a gzip-compressed `--input` body sent with `-H 'Content-Encoding: gzip'`. The guard judges the bytes as given and never looks at `-H`; the README says nothing. Whether api.github.com decompresses request bodies I don't know: that needs the live API. |
| F4 | src/protection.rs:46 | INFEASIBLE | introduced | On the `api` route, a mutation name in the `/graphql` path's query string (`?query=…`) is not scanned. This is outside the contract, which covers the body only. Whether GitHub reads a GraphQL query from the URL I don't know. Fix: also run `mutations` over the path. |

Judgement 3 has no finding. `delete-branch` refuses a `..` branch name in two places (`src/bot_args.rs:593`, `src/delivery.rs:346`). `gh` verbs are limited to release, pr, run, workflow, api and repo (`src/delivery.rs:352`). `publish` and token minting use fixed paths. `bot` git verbs make no API calls.

**5. Checked, no fault found**
- `gh api` value-taking short flags `fHXqtpF` match `gh api --help`.
- `-f` reads no file.
- Path readings: `%2e`/`%2E` dot segments, triple encoding, `;` matrix parameters, `%3F`, the `/repositories/` and `/organizations/` aliases.
- GraphQL aliases, and the path matched in any letter case.
- The guard runs before the policy is read and before `Github::bot()` on both routes.
- README and CHANGELOG don't state the refusal yet; the runbook (`.engineering/planning/runbook/protection-writes-wave.md:38`) makes them the coordinator's job, so it isn't a unit finding.

**6. Written outside the worktree**
- ~/.cache/gates-wave-ruleset-writes/review/scratch/security-2-alone.log
- ~/.cache/gates-wave-ruleset-writes/review/scratch/security-2-alone-2.log
- ~/.cache/gates-wave-ruleset-writes/review/scratch/security-2-suite.log
- `tempfile` sandboxes under ~/.cache/claude-tmp, deleted when each test ends

```findings
- file: tests/api_protection_writes.rs
  line: 283
  category: mutant
  severity: warning
  verdict: CONFIRMED
  origin: introduced
  message: graphql_mutation_behind_a_json_escape_is_refused carries no JSON unicode escape, so removing the unicode branch of json_unescaped leaves the unit's suite green
- file: src/main.rs
  line: 287
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: gh api files are judged on one read and re-read by gh after the token mint, so a caller rewriting its own file in that window is not covered
- file: src/protection.rs
  line: 63
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: a gzip-compressed --input body with a Content-Encoding header hides a mutation name from the guard; whether GitHub inflates request bodies is unknown
- file: src/protection.rs
  line: 46
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: the api route scans only the body of a /graphql request for mutation names, not a query string in the path; whether GitHub reads one there is unknown
```
