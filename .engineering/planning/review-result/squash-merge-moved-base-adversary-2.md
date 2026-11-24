---
format: aep.planning-md/3
id: review-result:squash-merge-moved-base-adversary-2
kind: review-result
status: active
title: 'Adversary pass 2: guards added after pass 1'
relations:
- reviews: story:squash-merge-moved-base
revision: 1
---
unit: round-2 guards of story:squash-merge-moved-base, commit 274c600 plus my uncommitted test additions
verdict: NEEDS-CHANGE (2 red: a forged commit-graph file defeats the new "head contains its own squash" check (introduced) and the ancestry walk itself (pre-existing))
cases: executed 24→30, red 2
origin: introduced 1 / pre-existing 1 / undecided 0
wrote-outside-worktree: 1 directory, <scratch>/
needs-coordinator: the walk finding (R2-F2) is pre-existing and outside round 2's diff; it shares a one-line fix with R2-F1. Decide whether it goes into this wave or the backlog.

## 1. Diff stat (against 274c600)
```
 tests/adversary_published_merge.rs | 266 ++++++++++++++++++++++++++++++++++++-
 1 file changed, 264 insertions(+), 2 deletions(-)
```
- Only the test file changed. `git diff 274c600 -- src` is empty.
- The 2 deleted lines are C: the comment on `PINS` now says it holds four of the five pins, all but `merge.renameLimit`, which the fixtures leave to the repository's config. The doc line of the fixture's `merge_tree` helper was reworded the same way.
- `cargo fmt --all --check` passes, and `cargo clippy --locked --test adversary_published_merge -- -D warnings` passes.
- All mutants and the fix probe ran in a scratch copy `<scratch>/mut2` (274c600); both source files there were restored and compared byte-identical.

## Findings

**R2-F1. Defect, CONFIRMED / NEEDS-CHANGE, introduced (B1).**
- **Attack:** write a commit-graph file (`.git/objects/info/commit-graph`, the file `git gc` or `git commit-graph write` leaves in a clone). In it, name the recorded base as the first parent of the commit between the squash and a head two commits above it. That head holds the squash's extra file.
- **Result 1:** `merge-base --is-ancestor <squash> <head>` exits 1. Git reads that intermediate commit's parents from the graph, not from the commit object, and does not check the graph's trailing checksum. `Git::is_ancestor` (`src/git.rs:619`) returns `Ok(false)`, so the check at `src/published_merge.rs:936` passes.
- **Result 2:** the merge base of parent and head becomes the recorded base, so `merge-tree` answers the tampered tree as a clean merge. The squash with a file in neither input is admitted.
- **Why it is reachable:** `Git::command` (`src/git.rs:540`) does not pass `core.commitGraph=false`, and `Git::new` refuses grafts and shallow files but not a commit-graph. The graph is a file in the local store, the same class as the grafts, shallow files and replace refs the gate already refuses.
- **Origin:** at `ba05649` this case is refused by the old base equality.
- **Test:** `adversary_squash_commit_graph_cannot_hide_that_the_head_contains_the_squash`, red.

**R2-F2. Defect, CONFIRMED / NEEDS-CHANGE, pre-existing (found under B1).**
- **Attack:** the same forged file in the ordinary ancestry walk. The chain is candidate → bot → person commit → published merge; the graph entry of the bot commit skips the person's commit.
- **Result:** `rev-list baseline..head` (`src/published_merge.rs:85`) never lists the person's commit, nothing else reads it, and the delivery is admitted. No squash is involved.
- **Origin:** red at `ba05649` as well.
- **Scope:** the other `rev-list` calls (`src/git.rs:882`, `src/published_merge.rs:766`) read the same graph. I did not test them.
- **Test:** `adversary_commit_graph_cannot_hide_a_person_commit_from_the_ancestry_walk`, red.

**Fix for both (named, not applied):** add `-c core.commitGraph=false` to `Git::command`. With that one line in the scratch copy, all 30 cases pass (`test result: ok. 30 passed`). The alternative is to refuse a commit-graph file in `Git::new`, as grafts are refused.

**R2-F3. Note, INFEASIBLE (B4).**
- **Attack:** exceed the pinned `merge.renameLimit=7000` itself (probe `probe-limit.sh`, 7100 files that both sides rename to different names with an edit each).
- **Result:** with the pin, the merge answers clean (exit 0). With the limit at 100000 it reports 7100 rename/rename conflicts (exit 1).
- **What reaches it:** only sources that both sides touch count against the limit, so it needs more than 7000 files renamed differently on both sides. No pull request of realistic size was found that does this. The clean tree holds only input content.

**R2-F4. Note, CONFIRMED, pre-existing wording newly reached (B2).**
- **Attack:** the head's loose commit object holds another commit's bytes.
- **Result:** refused at `ensure_merge_input`'s `rev-parse`, but the text is "Git rev-parse failed (exit 128): object <head> is not in the local object store; run `git fetch origin` and retry". The object is present but corrupt, and a fetch does not replace it.
- **Where:** `src/git.rs:577` `refusal()` takes "the existence probe failed" to mean "absent".
- **Test:** `adversary_squash_forged_head_commit_object_refuses`, green.

**R2-F5. Note, CONFIRMED, introduced (B5).**
- `main` prints only the outermost message (`src/main.rs:198`). For a merge that fails outright, that is now the partial-clone hint (`src/git.rs:709`), and "Git merge-tree failed (exit …)" stays only in the error chain.
- `missing()` probes only the two input commits. A missing merge-base commit or tree in a full clone gets the "in a partial clone, run …" hint too.
- It still refuses in every case, and no refusal that names a missing input commit is replaced.

## 2. Round-2 cases (in `tests/adversary_published_merge.rs`), state on 274c600, nextest times
| case | state | time |
|---|---|---|
| adversary_squash_commit_graph_cannot_hide_that_the_head_contains_the_squash (R2-F1) | RED | 0.36 s |
| adversary_commit_graph_cannot_hide_a_person_commit_from_the_ancestry_walk (R2-F2) | RED | 0.15 s |
| adversary_squash_commit_graph_tree_of_the_head_is_not_what_merge_tree_reads (B2, held) | green | 0.16 s |
| adversary_squash_forged_head_commit_object_refuses (B2, held; R2-F4) | green | 0.13 s |
| adversary_squash_rename_limit_from_included_config_cannot_lift_the_pin (B4, held: `include.path` and `includeIf`) | green | 0.28 s |
| adversary_squash_hand_made_pull_ref_does_not_change_the_verdict (B6, held) | green | 0.47 s |

The 15 round-1 cases all pass on 274c600. No case of mine runs over 5 s.

Red output, each run alone before any suite run:
```
adversary_squash_commit_graph_cannot_hide_that_the_head_contains_the_squash: panicked at tests/adversary_published_merge.rs:1331:5: a forged commit-graph hid that the head contains its own squash
adversary_commit_graph_cannot_hide_a_person_commit_from_the_ancestry_walk: panicked at tests/adversary_published_merge.rs:1373:9: a forged commit-graph hid a person's commit from the walk
```
These line numbers are from before rustfmt reflowed the file; the panics are now at :1337 and :1382.

## 3. Suite runs, after the cases existed
- `cargo test --locked --test adversary_published_merge`: exit 101. `test result: FAILED. 28 passed; 2 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.24s`. The two failures are R2-F1 and R2-F2.
- Count before the round-2 cases, measured with them deselected (`--skip commit_graph --skip forged_head_commit --skip included_config --skip hand_made_pull_ref`): `24 passed; 6 filtered out`.
- `cargo test --locked --test published_merge squash`: `test result: ok. 16 passed; 0 failed; ... 152 filtered out; finished in 1.55s`.
- At `ba05649` (scratch copy): the walk case is red; the containment case passes.

## Mutant table (round 2, scratch copy only; the two always-red commit-graph cases are left out)
| mutant | author's `published_merge squash` | my cases |
|---|---|---|
| R1 `is_ancestor(head, merge)` (:936) | caught: `a_squash_whose_recorded_head_contains_the_squash_refuses` | caught: `..._whose_recorded_head_is_the_squash_or_below_it...`, `..._heads_at_or_below_the_parent...` |
| R2 `!` dropped (:936) | caught (10) | caught (15) |
| R3 `Some(_) => Ok(false)` (git.rs:630) | caught: `a_squash_whose_head_history_cannot_be_read_refuses_on_the_ancestry_question` | **survives** |
| R4 `ensure_merge_input(git, parent, …)` (:930) | **survives** (16/16 green) | killed: `adversary_squash_forged_loose_head_tree_cannot_prove_an_extra_file`, `adversary_squash_forged_head_commit_object_refuses` |
| R5 base `^{commit}` compared with the parent (:910) | caught (11) | caught (14) |
| R6 `merge.renameLimit` pin removed (git.rs:689) | survives within the `squash` filter | killed: both round-1 rename-limit cases and `..._from_included_config...` |

## 4. Judgement findings
R2-F3, R2-F4 and R2-F5 above, covering commit 274c600.

## 5. Attacked and held
- B1: shallow and grafted history are refused by `Git::new` (`src/git.rs:506-522`). A missing intermediate commit refuses through `is_ancestor` (the author's test). The reverse error (a "yes" from Git although the head does not contain the squash) only refuses, so it cannot admit.
- B2: a commit-graph entry naming another root tree for the head is not used. `merge-tree` reads its two arguments through `parse_object` with a hash check, so the squash refuses.
- B2, not attacked further: a forged merge-base tree in the commit-graph only recombines parent and head content. The author left forged subtrees and blobs open.
- B3: an id that passes both the ancestry check and the `^{commit}` equality is a commit in the parent's history. Apart from R2-F1's graph forgery (a base proves no content), nothing else found.
- B4: `GIT_CONFIG_COUNT`, `GIT_CONFIG_PARAMETERS`, `include.path` and `includeIf` with `merge.renameLimit=1`, and `GIT_CONFIG_COUNT` with `merge.renames=false`, all lose to the `-c` pins (probe `probe-env.sh`, all exit 1).
- B5: `merge-tree` exits only 0, 1 or ≥128. The "failed outright" branch cannot be reached by a conflict.
- B6: a hand-made `refs/pull/7/head` pointing elsewhere changes no verdict (test).

Not tried:
- A rejected non-fast-forward update of an existing `refs/pull/<n>/head` by the named fetch (it has no `+`).
- Split commit-graph chains (`objects/info/commit-graphs/`).
- `GIT_COMMIT_GRAPH_PARANOIA`.
- The scanner's range under a forged graph.

## 6. Paths written outside the worktree
`<scratch>/`, which holds:
- round 1: everything listed in the round-1 report below;
- round 2 probes: `probe-env.sh`, `probe-limit.sh`, `probe-limit.out`, and their repositories `p6`, `p7`;
- round 2 mutants: `mutants2.sh`, `mutants2.out`, `pm2.pristine`, `git2.pristine`, `mut2-*.log`, and the copy `mut2/` (274c600) with its `target/`;
- round 2 logs: `build2.log`, `r2-*.log`, `base-r2.log`, `fix-probe.log`, `clippy2.log`, `nextest2.log`;
- the copy `base/` was reused, with the current test file.

## 7. Findings block
```findings
- file: src/git.rs
  line: 540
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: a commit-graph file in the local store makes merge-base --is-ancestor answer no for a head that contains its squash, so the new containment check passes and a squash with a file in neither input is admitted; Git::command does not set core.commitGraph=false
- file: src/published_merge.rs
  line: 85
  category: property
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: pre-existing
  message: the same commit-graph file removes a person's commit from rev-list baseline..head, so the ancestry walk admits a delivery whose history holds a non-bot commit
- file: src/git.rs
  line: 689
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: more than 7000 sources renamed by both sides exceed the pinned merge.renameLimit and the merge answers clean where exhaustive detection conflicts; no pull request of realistic size was found that reaches it
- file: src/git.rs
  line: 577
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: a present but corrupt head object is refused as "not in the local object store; run git fetch origin", a remedy that does not repair it
- file: src/git.rs
  line: 709
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: main prints only the outermost error, so a merge that fails outright shows only the partial-clone hint, which also appears in a full clone missing a merge-base object
```
