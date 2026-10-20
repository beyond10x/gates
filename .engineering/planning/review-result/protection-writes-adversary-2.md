---
format: aep.planning-md/3
id: review-result:protection-writes-adversary-2
kind: review-result
status: active
title: 'Adversary pass 2: protection write refusal'
relations:
- reviews: story:api-protection-writes
revision: 1
---
```
unit: story:api-protection-writes, tree ~/.local/state/worktree/trees/b10x/gates/gates-fix-protection-writes at f4aa077 plus one untracked test file
verdict: red (2 cases red; 2 findings: CONFIRMED 1, INFEASIBLE 1; no write admitted)
cases: executed 547→550, red 2
origin: introduced 2 / pre-existing 0 / undecided 0
wrote-outside-worktree: 6 paths
needs-coordinator: whether quadratic time on a constructed file holds the unit; this was the last pass, so it goes to a person
```

**1. Diff.** `git diff --stat` is empty because the only change is untracked: `?? tests/adversary_protection_writes_2.rs`. No `src/` or other path touched.

**2. Cases added** in `tests/adversary_protection_writes_2.rs`, run alone first (exit 101, 1 passed, 2 failed):

| Case (line) | Now | Red output, isolated run |
|---|---|---|
| `input_file_of_repeated_repos_segments_is_judged_within_bounded_time` | red | `judged in 60.001254526s, bound 20s; exit Some(124)` |
| `plain_input_file_of_the_same_size_is_judged_within_the_same_bound` (control) | green | the cap and bound alone do not fail |
| `standard_input_is_named_before_an_earlier_unreadable_file` | red | `gh api argument 4, the file it names (absent.txt), cannot be read (entity not found)` |

To check the growth rate I timed the debug binary directly on `repos/` repeated with no separator (`scale.sh`, no compile):

| Size | Time |
|---|---|
| 8 190 bytes | 1.8 s |
| 16 380 bytes | 7.6 s |
| 32 760 bytes | 31.8 s |

Doubling the size multiplies the time by about 4.2, so it is quadratic. Memory stayed under the 512 MiB cap.

**3. Suite run.** `b10x-build-slot cargo test --locked --no-fail-fast` gave exit 101: 548 passed, 2 failed, 550 executed. Only my 2 cases fail; the 12 pass-1 adversary cases are green. The "before" count, 547, is that same run with my file's 3 cases taken out. rustfmt `--check` passes, clippy `-D warnings` is clean, and `ess specify validate --path ess` gives `gates v1 — 3 file(s), valid`.

**4. Findings.** Both are in round-2 code, so `introduced`.

| # | Where | What was measured | What reaches it | Verdict, severity |
|---|---|---|---|---|
| 1 | src/protection.rs:437-440 | `path_in` copies and re-reads the whole rest of the view for every `repos`/`org` it finds, so time is quadratic: about 32 s at 32 KB, past 60 s at 128 KiB. Memory is now bounded (A7 holds); time is not | real route (`gh api --input`); constructed content, no real caller sends it; the local CLI only stalls, and nothing is sent | INFEASIBLE, warning |
| 2 | src/protection.rs:110,120 vs ess/domains/delivery.yaml (`standard-input` declared before `unreadable-file`) | The code keeps whichever of the two comes first in file order, but the ESS says outcomes are taken in declaration order over every argument and file | real route; built input (both in one request); both are `UncheckableInput`, only the named cause differs | CONFIRMED, note |

Round 2 rewrote three of my pass-1 cases: A3 is flipped to assert refusal, and the two A7 cases now assert refusal as undecodable. This matches the contract your brief states, so I have not raised it as a finding.

**5. What I attacked and could not break.**
- Round 2's new tests: each asserts a literal refusal or the token step, so none has a shape that cannot fail.
- The A1, A4 and A5 changes: the pass-1 cases for them are green, and the refusal no longer prints text after the `rulesets`/`protection` segment.
- The check order of the new A6 code: paths, then mutations, then undecodable text, then placeholder, then header matches the ESS, apart from finding 2.
- A write admitted: I added no new attempts for that direction this pass. By reading, the new `protection_prefix` gives the same verdict as the old `protected` for all four families, and the acceptance cases from 96 + 33 tests are green.

**6. Paths written outside the worktree.**
- `~/.cache/gates-wave-ruleset-writes/adversary-2/scratch/pass2-alone.log`
- `~/.cache/gates-wave-ruleset-writes/adversary-2/scratch/suite.log`
- `~/.cache/gates-wave-ruleset-writes/adversary-2/scratch/scale.sh`
- `~/.cache/gates-wave-ruleset-writes/adversary-2/scratch/scale/` (empty `bin/` and `config/`; the script deleted its body and output files)

The tests also create temporary directories under `~/.cache/claude-tmp`, removed on drop.

```findings
- file: src/protection.rs
  line: 440
  category: boundary
  severity: warning
  verdict: INFEASIBLE
  origin: introduced
  message: path_in copies and re-reads the rest of the view at every repos/org it finds, so a file of repos/ with no separator takes quadratic time (32 KB in 32 s, 128 KiB past 60 s) although memory is now bounded
- file: src/protection.rs
  line: 120
  category: contract-drift
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: an unreadable file named before standard input is reported instead of standard input, against the ESS statement that outcomes are taken in declaration order with standard-input first
```
