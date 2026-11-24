---
format: aep.planning-md/3
id: story:forged-local-store
kind: story
status: draft
title: Hash-check what the ancestry gate reads from the local object store
summary: Forged loose commit, subtree and blob objects still change what the walk and the merge proof read; policy publish runs unpinned Git
relations:
- informed_by: story:squash-merge-moved-base
revision: 1
---
## Problem

The ancestry gate reads the local object store, which is data the pusher controls. Two adversary
passes on story `squash-merge-moved-base` (records
`review-result:squash-merge-moved-base-adversary-1` and `-2`) showed files in that store that
change what Git answers while every object keeps its name. That story closed the ones with a
switch: `Git::command` now sets `core.commitGraph=false` and `core.multiPackIndex=false`. These
stay open, measured 2026-11-24 with Git 2.56.0:

1. A loose commit object that holds another commit's bytes hides a commit from
   `rev-list <baseline>..<head>` and turns `merge-base --is-ancestor` to "no", with both pins set.
   `rev-parse --verify <oid>^{commit}` fails on such an object, so a hash check exists.
2. A forged loose subtree or blob under a correct name is read by `git merge-tree` without a hash
   check, for a two-parent merge and for a squash. Only the top tree of each merge input is
   checked today (`ensure_merge_input`).
3. A pack's own `.idx` with two offsets swapped is expected to act like the multi-pack-index did;
   not built.
4. `policy publish` runs a path-limited `git log` outside `Git::command()` (`src/publish.rs`,
   function `git`), so it still reads a commit-graph file. A forged one in the operator's policy
   clone could make it name another commit and report "unchanged".
5. A present but corrupt object is refused as "not in the local object store; run `git fetch
   origin`", a remedy that does not repair it (`Git::refusal`).

Not established: whether a push can deliver a state built with 1, 2 or 3. The receiving side
hashes what it is sent, so an object sent under a wrong name may fail there. The forged
commit-graph was different: it left every object intact.

## Contract

- Red first for 1 and 2: the forged loose commit is refused by the walk; a forged loose subtree
  or blob under a merge input is refused by the merge proof.
- Every commit the walk lists, and every object a local merge reads, is hash-checked before its
  content decides a verdict; the cost on this repository's history is measured before and after
  and named.
- `publish.rs` `git()` carries the same pins as `Git::command`, with a case in the publish lane.
- A corrupt object refuses with a text that says corrupt, not absent.
- 3 is built as a probe; it gets a red case if it changes an answer after the hash checks.

## Acceptance

The red cases refuse; with each hash check removed its case is admitted again. The test step
stays inside its budget.

## Scope

- `src/git.rs` (`Git::command`, `Git::refusal`, `merge_tree`): cited.
- `src/published_merge.rs` (`verify`, `ensure_merge_input`): cited.
- `src/publish.rs` (`git`): cited.
- `tests/published_merge.rs`, `tests/policy_publish.rs`: inferred.
