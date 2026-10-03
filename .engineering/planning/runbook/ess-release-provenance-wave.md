---
format: aep.planning-md/3
id: runbook:ess-release-provenance-wave
kind: runbook
status: draft
title: 'ESS release dependency: reviewed update-branch provenance'
relations:
- delivers: story:github-update-branch-provenance
revision: 1
---
## Authority and boundaries

AEP implementing skill 0.19.1. The operator approved this single provenance unit and its independent review on 2026-10-03, and separately chose to retain b10x-bot release publication. Release and necessary dependency delivery are already authorized. One Gates PR; ESS publishing changes stay on one ESS integration PR. No policy baseline changes, history rewrite, bypasses or unrelated Gates primary edits.

## Selected unit and computed scope

Unit: story:github-update-branch-provenance, serving decisions as evidence (O2) through story:public-shared-gates. Computed active waves place this unit in wave 1, public-shared-gates in wave 2. Three inferred collisions with that umbrella story: CHANGELOG.md, Cargo.lock, Cargo.toml. Unassessed and cycle sets are empty. The existing umbrella is not concurrently dispatched. Scoper procedure and implementor/adversary procedures use native Codex agents; plugin-specific subagent types are not available. One bounded story does not need a multi-item decomposition critic panel.

## Checkouts and evidence

Coordinator managed id gates-update-branch-20261003; branch fix/github-update-branch-provenance; base 55625608260237a59fcc03136215b0a4e92f0d68. Resolve its path through worktree inspect. Coordinator session codex-ess-release-gates-01a0fc77 owns its lease. Build directory is target beneath the assigned worktree; scratch is the task-specific cache directory ess-release-dependencies-20261003. Worker checkouts and commits are recorded before dispatch. All executable repository changes are Rust.

The primary Gates checkout was behind remote main and held existing edits to src/git.rs, src/published_merge.rs and tests/published_merge.rs. Those edits remain untouched; the managed checkout begins at exact current remote main. Preflight: 15 GiB persistent disk free, 27 GiB tmpfs free, 34 GiB available RAM. Only one Gates compiler runs at a time, and storage is checked before building. Source output is recoverable through published commits or managed archives, never manual tree removal.

## Sequence and commits

Record plan and verified planning compatibility migration; implement the synthetic failing reproduction and narrow authenticated proof; run focused tests; independently attack and record mutation evidence; integrate reviewed source; run full required Gates checks; publish one PR through the App; verify Gates release binary and checksum before adopting it for ESS. Planned commits cover the compatibility migration, governed plan, source/test fix, review evidence and release metadata. The ESS release remains blocked until exact ancestry verification and compliant publication both work.

## Current stage

Planning active. Migration verified 8 artifacts, 14 transitions and 13 evidence records without semantic changes. Read-only scoper is assessing the exact proof and refusal matrix. Implementation has not started.
