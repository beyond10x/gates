---
format: aep.planning-md/3
id: review-result:update-branch-chain-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: earlier update-branch commit'
relations:
- reviews: story:update-branch-chain
revision: 1
---
unit: 2
verdict: green
cases: executed 123→132, red 0
origin: introduced 3, pre-existing 0, undecided 0
wrote-outside-worktree: none
needs-coordinator: no

None of my 9 cases fails against the tree. Findings cover commit `9b05c62` plus my uncommitted test additions. The check never admits content of its own: every admitted earlier update must equal Git's clean local merge of its parents, and every commit in the delivered range is still checked by the delivery walk. The findings are weak tests and one shape the earlier path now admits.

**1. Diff** (test file only, no `src/` change)
```
 tests/published_merge.rs | 314 +++++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 314 insertions(+)
```

**2. Cases added** (`tests/published_merge.rs`, run alone first: `9 passed; 0 failed; 112 filtered out`, EXIT=0)

To test whether the unit's tests would notice each check being removed, I mutated a copy of the crate in `target/scratch/adv-unit2/mutant`. The tree's `src/` was never touched. With each mutant, all 112 of the unit's cases stayed green and one of my cases failed:

| Mutant (removed from `src/published_merge.rs`) | My case that fails (line) | Printed at `tests/published_merge.rs:2481:32` |
|---|---|---|
| M1: identity and shape check, :586-592 | `person_commit_above_an_earlier_update_refuses_outside_the_range` (2768), `one_parent_github_commit…` (2795) | `a person's commit above an earlier update, outside the delivered range admitted through verify_publication: ()` |
| M2: two-parent check only, :589-592 | `one_parent_github_commit_above_an_earlier_update_refuses` (2795) | `a one-parent GitHub commit … admitted through verify_publication: ()` |
| M3: `completed.len() == 1`, :599 | `head_line_update_shared_with_a_second_merged_pull_request_refuses` (2813), `head_line_associations_are_read_to_the_last_page` (2842) | `a head-line update shared with a second merged pull request admitted through verify_publication: ()` |
| M4: refusal on an empty first-parent line, :575-577 | `pull_request_head_below_the_update_refuses` (2877) | `a pull request head below the update admitted through verify_publication: ()` |
| M5: `ensure_published(merge)` on the earlier path, :538 | `earlier_update_with_an_unpublished_merge_refuses` (2900) | `an earlier update whose pull request merge is not published admitted through verify_publication: ()` |

All my cases are green on the tree: the 6 above plus 2693, 2756 and 2914.

**3. Suite** (after my cases existed): `cargo test --locked --test published_merge --test adversary_published_merge --lib` gives 2 + 9 + 121 passed, EXIT=0. The "before" count comes from the same run with `--skip adversary_unit2_`: 112 passed, 9 filtered out. `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D warnings` both exit 0. I ran rustfmt on my own section only.

**4. Findings**

| # | Location | Verdict / origin | Measured | What reaches it |
|---|---|---|---|---|
| F1 | `tests/published_merge.rs:2559` `intermediate_non_bot_commit_refuses` | CONFIRMED / introduced | It stays green under M1. The person's commit is inside the delivered range, so the delivery walk refuses that commit itself. | A branch cut from the pull request after an earlier update and delivered on its own. The head line is then outside the range. My case 2768 covers it. |
| F2 | `src/published_merge.rs:538, 575, 589, 599` | CONFIRMED / introduced | The unit's suite misses M2–M5. My cases now catch each. | M2 and M3: the same cut-branch flow as F1. M4: nothing found. M5: only if the default branch loses an already-published merge, which the public non-fast-forward rule prevents; nothing found. |
| F3 | `src/published_merge.rs:530` (no parent-order check on the earlier path) | INFEASIBLE / introduced | An update with reversed parents (base, head) is refused as the final head ("final merge parents are not the update base…") but admitted as an earlier update `[Ok(()), Ok(())]`. Probe log: `target/scratch/adv-unit2/probe-reversed.log`. Its content is still the clean merge of its parents. The story requires only two distinct parents, so I added no red case. | Nothing found: GitHub's update-branch always writes (head, base). |

**5. Attacked and could not break**
- **Real changes:** the twice-updated graph with real file changes on every side, public and private, is admitted. Before this, every case shared one tree.
- **First-parent line:** an update reachable only through a base parent, an empty line, and a summary head equal to the merge all refuse.
- **Associations:** an update tied to two merged pull requests refuses. Pull-request records refuse when they come from a fork or another repository id, target another branch, are unmerged, were merged by another account, or (private) were opened or merged by a non-bot account. A summary missing its head refuses.
- **Pagination:** head-line association pages are read to the last page, and a duplicate on page 2 refuses.
- **Branch cut from the earlier update without the merge:** admitted when the commits above it are clean. It refuses with a person's commit above it, a one-parent GitHub commit, or a second merged pull request.
- **Pre-existing refusals:** all still pass, including squash, rebase-shaped and advanced-final-base.

**6. Paths written outside the worktree:** none. Scratch inside the tree is `target/scratch/adv-unit2/` (607M, including the mutant crate copy and its own `target/`), left for you to clean up.

```findings
[
  {"file": "tests/published_merge.rs", "line": 2559, "category": "mutant", "severity": "warning", "verdict": "CONFIRMED", "origin": "introduced", "message": "intermediate_non_bot_commit_refuses stays green with the head-line identity check deleted (mutant M1) because the delivery walk refuses the in-range commit itself"},
  {"file": "src/published_merge.rs", "line": 538, "category": "mutant", "severity": "warning", "verdict": "CONFIRMED", "origin": "introduced", "message": "the two-parent check, completed.len()==1, the empty-line refusal and ensure_published(merge) on the earlier path each survive the unit's suite (M2-M5); the adversary_unit2_* cases now catch each"},
  {"file": "src/published_merge.rs", "line": 530, "category": "judgement", "severity": "note", "verdict": "INFEASIBLE", "origin": "introduced", "message": "an update with reversed parents (base, head) is refused as the final head but admitted as an earlier update; content-safe and not produced by GitHub update-branch"}
]
```
