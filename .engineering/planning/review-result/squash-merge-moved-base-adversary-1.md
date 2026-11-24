---
format: aep.planning-md/3
id: review-result:squash-merge-moved-base-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: squash proof against the moved base'
relations:
- reviews: story:squash-merge-moved-base
revision: 1
---
unit: squash proof of story:squash-merge-moved-base, commit 8aef4f9 (worktree gates-squash-base-head plus my uncommitted test additions)
verdict: NEEDS-CHANGE (1 defect), plus 2 INFEASIBLE weaknesses that are red
cases: executed 9→24, red 4
origin: introduced 3 / pre-existing 1 / undecided 0
wrote-outside-worktree: 1 directory, <scratch>/
needs-coordinator: decide whether the two INFEASIBLE red cases (F2, F3) stay red or get dropped

## 1. Diff stat
```
 tests/adversary_published_merge.rs | 707 +++++++++++++++++++++++++++++++++++++
 1 file changed, 707 insertions(+)
```
- Only a test file changed. `git diff 8aef4f9 -- src` is empty.
- I never edited `src/` in the worktree, not even briefly. Every mutant ran in a scratch copy.
- `.engineering/planning/story/test-step-budget.md` shows as untracked in the worktree. This pass did not write it.
- `cargo fmt --all --check` passes, and `cargo clippy --locked --test adversary_published_merge -- -D warnings` passes.

## Findings

**F1. Defect, CONFIRMED / NEEDS-CHANGE, introduced on the squash path (the cause in `src/git.rs` is pre-existing).**
- **Attack:** set `merge.renameLimit=1` (or `diff.renameLimit=1`) in the repository's own config. Both sides rename the same two files to different names, each with an edit.
- **Result:** Git's defaults report a rename/rename conflict. With the setting, the merge comes back clean with all four names, so the squash is admitted.
- **Why:** `src/git.rs:637-648` fixes the rename settings (`merge.renames`, `diff.renames`, `merge.directoryRenames`) but not either rename limit. `src/git.rs:697-703` refuses only `merge.default` and `*.driver`. The decision is at `src/published_merge.rs:908-916`.
- **Same gap for ordinary merges:** the two-parent check at `src/published_merge.rs:858-866` has the same hole. Its test is also red when run against base `ba05649`, so that part is pre-existing. The squash case is refused at `ba05649` ("squash merge parent is not the pull request base"), so the squash exposure is new.
- **What reaches it:** the clone's own `.git/config`. This is the same class the repository already tests in `repository_merge_config_cannot_make_a_conflicting_merge_clean` (tests/published_merge.rs:2181).
- **Effect:** the steered tree holds only the two inputs' content, but a real conflict passes as clean.
- **Suggested fix (not applied):** also pass `-c merge.renameLimit=<Git's default>` in `Git::merge_tree`. A `merge.renameLimit` given on the command line also overrides `diff.renameLimit`.

**F2. Weakness, INFEASIBLE, introduced.**
- **Attack:** the pull request record's `head.sha` is the squash commit itself, or a commit built on top of it (the candidate).
- **Result:** the squash is admitted with a file that is in neither the parent nor the real head. `merge-tree(parent, head)` returns the squash's own tree, so check 3 compares the squash with itself.
- **Where:** `src/published_merge.rs:895-916` has no check that the head is not the merge or above it.
- **What reaches it:** nothing found. GitHub fixes `head.sha` at merge time. A pull request "merged" by pushing its head would leave two pull requests naming the same commit, and that refuses at :411.
- **Suggested fix:** refuse when `merge-base --is-ancestor <merge> <head>` succeeds.

**F3. Weakness, INFEASIBLE, introduced on the moved-base shape.**
- **Attack:** overwrite the loose object file of the head's real tree with another tree's bytes (the local store is attacker-controlled data).
- **Result:** the squash is admitted with an extra file. `git merge-tree` reads the head's tree without checking its hash; `cat-file -p` does check it (probe: "hash mismatch").
- **Where:** nothing in the squash check reads the head tree through a hash-checking path (`src/published_merge.rs:896-908`). In `github_commit`, `cat-file -e <tree>^{tree}` at `src/published_merge.rs:139` and `:147` happens to verify only the top-level trees of the squash and its parent.
- **What reaches it:** it only pays off with a GitHub-signed squash whose tree is not the merge of its real inputs, and GitHub does not produce one.
- **Same class:** subtrees and blobs read by the two-parent check are open the same way (pre-existing).

**F4. Note, INFEASIBLE, no test written.**
- **Attack:** the recorded base is an annotated tag object that points to an ancestor of the parent.
- **Result:** check 1 accepts it, because `merge-base --is-ancestor` follows the tag to its commit (probe `probe-tag-base.sh`: exit 0). Decided at `src/published_merge.rs:889-891`.
- GitHub's `base.sha` is always a commit, and the base adds no content.

**F5. Weakness (availability), CONFIRMED, introduced.**
- **Attack:** a `--filter=blob:none` clone holding a squash whose merge needs blob content (an inexact rename).
- **Result:** refused, never admitted. After running the fetch the refusal for an absent head names (`fetch origin refs/pull/<n>/head`), the merge still fails with "Git merge-tree failed (exit 128)" and names no remedy. That fetch brings no blobs in a blob-less clone, so the named remedy never helps.
- **Where:** `src/git.rs:654-657` and `:587-608`. Measured by `adversary_squash_partial_clone_without_blobs_refuses_rather_than_admits` (green).

**F6. Judgement, pre-existing (0.1.28 is the same).**
- On a public repository, a head committed by a person is admitted: the head's commits are not walked (`adversary_squash_head_commits_are_not_walked_on_a_public_repository`, green).
- The comment at `src/published_merge.rs:877-879` says the head rests on the branch ruleset. The module doc (:8-11) and the CHANGELOG entry do not say so.

**Item 6 (regressions against 0.1.28):** F1, F2 and F3 are admitted on a moved base where 0.1.28 refused. Each is red on 8aef4f9; the squash variants pass at `ba05649`. None of them is "the default branch advanced and the tree is the clean local merge" in the intended sense. Nothing else found. Onto the recorded base itself, 0.1.28 admitted every tree.

## 2. Cases added (`tests/adversary_published_merge.rs`), state on 8aef4f9, nextest times
| case | state | time |
|---|---|---|
| adversary_squash_rename_limit_config_cannot_make_a_conflicting_squash_clean (F1) | RED | 0.26 s |
| adversary_rename_limit_config_cannot_make_a_conflicting_two_parent_merge_clean (F1, pre-existing) | RED | 0.22 s |
| adversary_squash_whose_recorded_head_is_the_squash_or_below_it_refuses (F2) | RED | 0.23 s |
| adversary_squash_forged_loose_head_tree_cannot_prove_an_extra_file (F3) | RED | 0.23 s |
| adversary_squash_parent_off_the_proved_line_is_walked_and_refused | green | 0.18 s |
| adversary_squash_tree_holding_more_than_the_pull_request_refuses (extra file, head tree, parent tree, mode 100755, symlink in place, extra gitlink, extra symlink) | green | 2.42 s |
| adversary_squash_content_in_a_path_both_sides_touched_must_be_the_merge | green | 0.41 s |
| adversary_squash_heads_at_or_below_the_parent_are_admitted_only_as_the_parent_tree | green | 0.76 s |
| adversary_squash_unrelated_head_refuses | green | 0.24 s |
| adversary_squash_criss_cross_head_is_admitted_only_as_the_recursive_merge | green | 0.47 s |
| adversary_squash_directory_rename_resolved_as_a_move_refuses | green | 0.23 s |
| adversary_squash_recorded_base_that_is_no_ancestor_commit_refuses (tree, blob, squash itself, unmerged head, commit above the squash) | green | 1.69 s |
| adversary_squash_head_through_a_tag_or_a_replace_ref_refuses | green | 0.44 s |
| adversary_squash_partial_clone_without_blobs_refuses_rather_than_admits (F5) | green | 0.47 s |
| adversary_squash_head_commits_are_not_walked_on_a_public_repository (F6) | green | 0.31 s |

No case of mine runs over 5 s; the slowest in the binary (6.6 s) is an existing case.

Red output, each case run alone before any suite run:
```
adversary_squash_rename_limit_config_cannot_make_a_conflicting_squash_clean: panicked at tests/adversary_published_merge.rs:746:13: merge.renameLimit=1 made a conflicting squash clean: admitted
adversary_rename_limit_config_cannot_make_a_conflicting_two_parent_merge_clean: panicked at :746:13: merge.renameLimit=1 made a conflicting merge clean: admitted
adversary_squash_whose_recorded_head_is_the_squash_or_below_it_refuses: panicked at :831:9: a squash proved against itself was admitted (head below the squash: false)
adversary_squash_forged_loose_head_tree_cannot_prove_an_extra_file: panicked at :864:5: a forged loose head tree proved a file in neither real input
```
These line numbers are from before rustfmt reflowed the file.

## 3. Suite runs, after the cases existed
- `cargo test --locked --test adversary_published_merge`: exit 101. `test result: FAILED. 20 passed; 4 failed; 0 ignored; 0 measured; 0 filtered out; finished in 5.30s`. The four failures are the red cases above.
- Count before my additions, measured on the same binary with my cases skipped (`--skip adversary_squash --skip adversary_rename_limit`): `9 passed`.
- `cargo test --locked --test published_merge squash`: exit 0. `test result: ok. 12 passed; 0 failed; ... 151 filtered out; finished in 1.28s`.
- Origin run on a copy of `ba05649` with my test file: the two-parent F1 case is red there ("admitted"). The F1 squash case refuses there with "squash merge parent is not the pull request base". The F2 and F3 cases pass there.

## Mutant table
Scratch copy only; the copy was restored and compared byte-identical afterwards. "Caught by" lists the tests that fail besides the four always-red ones.

| mutant | author's squash tests | my cases |
|---|---|---|
| M1 swap `--is-ancestor` arguments (:890) | caught (9 fail, including `..._moved_is_admitted...`) | caught |
| M2 compare with the head's tree instead of the squash's (:914) | caught (`..._moved_is_admitted...`, `..._file_beyond...`) | caught |
| M3 drop `kind == "commit"` (:898) | caught, but only through the message text in `a_squash_whose_pull_request_head_is_not_a_commit_refuses` | caught for a behavioural reason: `adversary_squash_head_through_a_tag_or_a_replace_ref_refuses` (a tag head would be admitted) |
| M4 `merge_tree(base, head)` instead of the parent (:908) | caught (4) | caught |
| M5 drop `local.clean` (:910) | caught (`a_squash_whose_head_conflicts...`) | caught (`..._directory_rename_...`) |
| M6 check 1 asks about the squash instead of its parent (:890 `base, merge`) | **survives** (12/12 green) | killed by `adversary_squash_recorded_base_that_is_no_ancestor_commit_refuses` (base = the squash) |
| M7 check 1 removed (`parent, parent`) | caught (3) | caught |
| M8 `merge_tree(head, parent)` (argument order) | survives | survives; no failure found, merge output does not depend on argument order in any tested case |
| M9 parent replaced by the published head (:884) | caught (2) | caught |

## 4. Judgement findings
F4 and F6 above, covering commit 8aef4f9.

## 5. Attacked and held
- A parent off the proved line is always walked or below the baseline (`src/published_merge.rs:78-97`).
- Tree differences refuse: extra file, mode, symlink, gitlink, head-only tree, parent-only tree, one extra line in a file both sides touched.
- Criss-cross bases give the recursive merge only.
- An unrelated head refuses (merge-tree refuses unrelated histories).
- Empty squashes (head equal to the parent or below it) are admitted only as the parent's tree.
- A directory rename refuses as a conflict.
- Base as a tree, blob, the squash, the unmerged head or a later commit refuses.
- A head named through a tag refuses ("not a commit").
- A replace ref is ignored (`--no-replace-objects`, git.rs:543).
- Grafts and shallow files are refused at `Git::new` (git.rs:506-522); I did not re-test them.
- `info/attributes` and merge drivers are refused (git.rs:678-708); existing tests cover them.
- `verify_update_branch` and `verify_earlier_update` refuse a squash through `ordinary_only` (`src/published_merge.rs:840-845`; existing `unsupported_update_branch_shapes_refuse`).
- `diff.algorithm` in repository config: 300 random 3-way merges showed no change in clean/conflict, so no effect was shown.

Not tried:
- A SHA-1 collision head.
- Alternates (`objects/info/alternates`).
- Git environment variables set by the caller.
- `core.ignoreCase`.
- Whether GitHub's own squash ever differs from local merge-tree.
- Whether GitHub ever updates `head.sha` on a merged pull request.

## 6. Paths written outside the worktree
`<scratch>/`, which holds:
- probes `probe-rename.sh`, `probe-algo.sh`, `probe-partial.sh`, `probe-forge.sh`, `probe-tag-base.sh` and their repositories `p1`–`p5`;
- `mutants.sh`, `mutants.out`, `published_merge.rs.pristine`, `mut-*.log`;
- the copies `base/` (ba05649) and `mut/` (8aef4f9), each with its own `target/`;
- the logs `build1.log`, `red-*.log`, `suite1.log`, `nextest1.log`, `pm-squash.log`, `base-run.log`, `fmt.log`, `clippy.log`.

## 7. Findings block
```findings
- file: src/git.rs
  line: 637
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: merge.renameLimit or diff.renameLimit in repository config makes a rename/rename conflict merge clean, so a squash (and, pre-existing, a two-parent merge) is admitted as Git's clean merge; the rename limit is not fixed in Git::merge_tree
- file: src/published_merge.rs
  line: 908
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: a record head equal to the squash or above it makes merge-tree return the squash's own tree, so an extra file is admitted; GitHub fixes head.sha at merge, so no path to it was found
- file: src/published_merge.rs
  line: 908
  category: property
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: merge-tree reads the head's tree without a hash check, so a forged loose object proves an extra file; it pays off only with a GitHub squash whose tree is not the merge of its inputs
- file: src/published_merge.rs
  line: 890
  category: boundary
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: check 1 accepts an annotated tag object as the recorded base because merge-base follows it to its commit
- file: src/git.rs
  line: 657
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: in a blob-less partial clone a squash whose merge needs blob content refuses with "Git merge-tree failed (exit 128)" and no remedy, and the named refs/pull/<n>/head fetch brings no blobs
- file: src/published_merge.rs
  line: 877
  category: judgement
  severity: note
  verdict: CONFIRMED
  origin: pre-existing
  message: on a public repository the squash head's commits are not walked (a person-committed head is admitted); the code comment says so, but the module doc and CHANGELOG do not
```
