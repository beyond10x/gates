---
format: aep.planning-md/3
id: story:merge-gitlink-worktree-state
kind: story
status: draft
title: Refuse a local merge that worktree state can turn clean through a gitlink
summary: merge-tree answers clean for a gitlink conflict when the submodule repository is present in the worktree
relations:
- informed_by: story:squash-merge-moved-base
revision: 1
---
## Problem

`Git::merge_tree` (`src/git.rs`) recomputes a merge to prove that a commit GitHub committed adds
nothing of its own. A conflicted merge must refuse. One conflict turns clean through state that
is not a configuration key, so no `-c` pin covers it: when both inputs move the same gitlink and
one of the two submodule commits contains the other, `git merge-tree --write-tree` answers exit 1
without the submodule's repository and exit 0 when that repository is present at the gitlink's
path in the worktree. Measured 2026-11-24 with Git 2.56.0 while story
`squash-merge-moved-base` was built (probe output kept only in that session's scratch directory).

The README says that nothing in the checkout running the proof can resolve a conflict. This case
contradicts that sentence for both merge shapes (two-parent and squash). It is older than the
squash change.

Not established: whether a delivery can reach this merge at all. The scanner refuses submodules,
so a candidate that holds a gitlink may be refused before the ancestry gate runs.

## Contract

- Red first: a fixture in `tests/published_merge.rs` whose two merge inputs both move one
  gitlink, with the submodule's repository present in the worktree, shows the admitted merge.
- A local merge whose two inputs both change the same gitlink refuses, whatever the worktree
  holds; or the merge runs where no worktree state can reach it. The story's implementor picks
  the one the red case supports and says why.
- If the scanner already refuses every delivery that holds a gitlink before this merge runs, the
  story ends with a test that shows that order, and the README sentence is made exact.

## Acceptance

The red case refuses after the change, for a two-parent merge and for a squash; with the guard
removed it is admitted again.

## Scope

- `src/git.rs` (`merge_tree`): cited.
- `tests/published_merge.rs`: cited.
- `README.md` (the sentence about the checkout): cited.
