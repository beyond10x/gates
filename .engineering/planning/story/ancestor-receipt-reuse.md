---
format: aep.planning-md/1
id: story:ancestor-receipt-reuse
kind: story
status: implemented
title: A push scans only the commits no verified receipt covers
scope:
- confidence: inferred
  path: src/evidence.rs
- confidence: inferred
  path: src/git.rs
- confidence: inferred
  path: src/hooks.rs
- confidence: inferred
  path: src/main.rs
revision: 8
---
## Context

`b10x-gates check`, and the pre-push hook that runs it, rescan every commit since a repository's
adoption baseline on every new head (`src/git.rs` `candidate`, ~lines 238–300). A retained receipt
is reused only for the same head (`src/main.rs` ~412–419, `src/hooks.rs` ~277–289). The cost grows
with every commit.

Measured 2026-09-29 on a consumer repository (the knowledge runtime): 117 commits since its
baseline, 21,149 changed file versions totalling 53.1 MB, each also read with its predecessor, each
blob read through 2 `git` processes (`cat-file -s`, `cat-file blob`); one `b10x-gates check` of a
release commit took 628 s, although that commit's own hook had just signed a receipt for its parent
chain.

## Build

1. **Batched object reads.** Read object sizes and blob bytes through one long-running
   `git cat-file --batch` (or `--batch-check` plus `--batch`) per candidate instead of one process per
   blob, with the same `MAX_BLOB` and `MAX_TOTAL` limits and the same refusals.
2. **Ancestor receipt reuse.** When a retained receipt verifies (signature by an enrolled signer,
   same repository, same policy digest, same scanner version, its head an ancestor of the candidate
   head and a descendant of the baseline), scan only the commits in `<receipt head>..<candidate head>`
   (every commit reachable from the head and not from the receipt head, merged side branches
   included), then sign a receipt for the candidate head as today. Choose the verified ancestor
   receipt that leaves the fewest commits to scan. Per-commit units are computed against each
   commit's own parent, as today, so the units scanned for those commits are the same as in a full
   scan.
3. Tag objects are always scanned in full, as today.

The receipt format and what a receipt states do not change: it still states that the common checks
passed for every commit from the baseline to its head.

## Acceptance

- A candidate whose parent has a valid retained receipt is scanned over exactly the new commit's
  units (a test counting units handed to the scanner).
- A retained receipt with a bad signature, another policy digest, another scanner version, another
  repository, or a head that is not an ancestor causes a full scan (one case each; each fails when
  its guard is removed, with mutation evidence recorded).
- A merge of a side branch not covered by the ancestor receipt scans the side branch's commits.
- On a repository with 100+ commits since baseline and a receipt for the parent, `check` of one new
  commit finishes in under 10 s (a timing test or a recorded measurement).
- A verified receipt for the exact head still causes zero scanner invocations.
- `cargo test --locked`, `cargo fmt --all --check`, `cargo clippy --all-targets --locked -- -D warnings`.
