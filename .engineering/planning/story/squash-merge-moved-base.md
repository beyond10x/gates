---
format: aep.planning-md/3
id: story:squash-merge-moved-base
kind: story
status: implemented
title: Admit a squash merge made after the default branch moved
summary: Prove a squash by ancestry of the recorded base and a recomputed merge of parent and pull request head, not by base equality
relations:
- informed_by: story:published-merge-delivery
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-11-24T20:04:28Z", actor: "human:operator", revision: 2}
- {from: "proposed", to: "active", at: "2026-11-24T20:04:28Z", actor: "human:operator", revision: 3}
- {from: "active", to: "implemented", at: "2026-11-24T20:12:43Z", actor: "human:operator", revision: 4, decided_on: {"recorded":{"test_result":1,"review_outcome":3},"asserted":{"test_result":1,"review_outcome":3}}}
---
## Problem

b10x-gates 0.1.28 refuses every bot push whose ancestry holds a squash merge that GitHub made
after the default branch had moved: "squash merge parent is not the pull request base"
(`src/published_merge.rs:882`). The check compares the squash commit's parent with `base.sha` of
the pull request record. GitHub squashes a pull request onto the head of the base branch at merge
time. `base.sha` on the record is the base branch head from an earlier moment (when the pull
request was opened or last updated), so the two differ whenever another pull request merged in
between.

Observed 2026-11-24 in a public repository of this organization: pull request 49 records
`base.sha` `f09c740f`; two other pull requests merged first; the squash commit `dce29db7` has
the parent `fff33d17`, the default branch head at merge time. `f09c740f` is an ancestor of
`fff33d17`. Every later bot push of a branch cut from that default branch is refused, and no push
can succeed again until the check changes. `b10x-gates check` passes on the same branch; the
refusal comes from the ancestry gate at push.

Recomputed on that case: `git merge-tree --write-tree fff33d17 <pull request head af34d2f9>`
answers the tree `67e3f8a9`, which is the tree of `dce29db7`.

## The property the check protects

`published_merge::verify` is the ancestry gate of delivery: every commit after the enrolled
baseline carries the exact bot author and committer, except a commit GitHub itself committed for a
merged pull request. Such a commit is admitted only when it adds nothing of its own: all of its
content comes from inputs that are proved separately. For a two-parent merge the inputs are its
parents (the base is walked ancestry, the head commits are bot commits in the same walk) and the
proof is that its tree equals Git's clean merge of the two, recomputed locally
(`src/published_merge.rs:846-861`).

A squash has one parent, so the pull request head is outside the walked ancestry. Its inputs are
the parent (walked ancestry) and the pull request head named by the authenticated pull request
record (written by the App alone under the public branch authority). 0.1.28 does not prove the
tree against those inputs (`src/published_merge.rs:871-873` says so); it compares the parent with
`base.sha` instead, and line 886 asks whether a commit descends from its own parent, which is
always true.

Without a check at this place, a single-parent commit with the GitHub committer that a merged pull
request record names as its merge would be admitted whatever its tree holds. Content that is in
neither the walked ancestry nor the pull request head (content no bot commit carries) would enter
delivered ancestry under the bot's delivery.

## Contract

A squash merge is admitted when all of these hold, in addition to every check that runs before
them today (shape, published default branch, remote commit and signature, association, merged by
the exact bot, same repository, default-branch target, public repository only):

1. The pull request's recorded `base.sha` is the squash parent or an ancestor of it. The parent
   may be later than the recorded base; it may not be on a history that does not contain it.
2. The pull request head (`head.sha` of the authenticated record) is a commit in the local object
   store. When it is absent the gate refuses and names the commit and the fetch that supplies it
   (`refs/pull/<n>/head`). The gate makes no network fetch of its own here.
3. Git's local merge of the parent and the pull request head (`Git::merge_tree`, the same
   function the two-parent proof uses) is clean, and its tree equals the squash commit's tree.

The equality `base.sha == parent` is removed. The check at line 886 (`merge-base --is-ancestor
<parent> <squash>`, true for every commit and its parent) is replaced by guard 1, which asks the
question that line was written for with the two commits that can differ. Nothing is accepted
through an allowlist of commits or a policy entry. A private repository still refuses a squash.

## Old equality against the new guards

- Still refused, as the equality refused it: a squash whose parent is not the recorded base and
  does not descend from it (a parent on another line, a base rewritten after the pull request
  recorded it).
- Now accepted, where the equality refused it: a squash whose parent is a descendant of the
  recorded base (the default branch advanced before the merge), only when its tree is the clean
  local merge of that parent and the pull request head.
- Now refused, where the equality admitted it: a squash onto the recorded base itself whose tree
  is not the clean local merge of that base and the pull request head, and a squash whose pull
  request head is not in the local object store.

## Acceptance

`tests/published_merge.rs`, each timed, none over 5 s:

- red before the change, green after: a squash whose parent is the default branch head at merge
  time, with the recorded base two merges earlier, is admitted;
- a squash whose tree holds one file more than the merge of parent and head refuses, naming the
  local merge;
- a squash whose pull request head conflicts with the parent refuses;
- a squash whose recorded base is not an ancestor of the parent (a parent on another line, a
  rewritten base) refuses;
- a squash whose pull request head object is absent refuses and names the fetch;
- the existing squash tests (public admitted, private refused, named and unlisted forms) keep
  their verdicts; the "onto another base" cases keep refusing.

Mutation evidence, recorded in the pull request: with guard 1 removed the base test fails; with
guard 3's equality removed the extra-file test fails; with guard 3's clean check removed the
conflict test fails.

## Not covered

- The gate does not fetch a missing pull request head itself.
- The head commits of a squashed pull request are not walked one by one; as in 0.1.28 that rests
  on the public branch authority, so a private repository stays refused.
- GitHub's squash of a pull request whose merge differs from Git's own `merge-tree` result (a
  rename heuristic that differs) refuses, as it does today for a two-parent merge.

## Scope

- `src/published_merge.rs` (`verify_terminal_merge`, squash branch): cited.
- `tests/published_merge.rs` (squash fixtures and cases): cited.
- `CHANGELOG.md` `## [Unreleased]`: cited.
- `src/git.rs`: inferred, only if the missing-object refusal needs a helper.
