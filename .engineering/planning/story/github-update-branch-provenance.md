---
format: aep.planning-md/3
id: story:github-update-branch-provenance
kind: story
status: active
title: Prove published bot-created GitHub update-branch ancestry
relations:
- derived_from: story:public-shared-gates
scope:
- confidence: inferred
  path: CHANGELOG.md
- confidence: inferred
  path: Cargo.lock
- confidence: inferred
  path: Cargo.toml
- confidence: cited
  path: src/published_merge.rs
- confidence: cited
  path: tests/adversary_published_merge.rs
- confidence: cited
  path: tests/published_merge.rs
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-10-03T07:20:10Z", actor: "human:timo", revision: 4}
- {from: "proposed", to: "active", at: "2026-10-03T07:20:10Z", actor: "human:timo", revision: 5}
---
## Authorization and problem

The operator explicitly approved implementing and independently reviewing this provenance fix on 2026-10-03 as a dependency of the ESS release. Preserve main history and every existing delivery safeguard. ESS main contains a GitHub update-branch commit accepted as the head of a later bot-merged pull request. The current verifier mistakes every GitHub-committed ancestor for a final PR merge and refuses the intermediate update commit with `merged pull request missing or ambiguous`.

## Required behavior

Authenticate authority for a GitHub-created branch update only through exact repository identity, App-only branch authority, bot author, GitHub committer and valid signature, local/remote object agreement, and a completed same-repository bot merge into authenticated default-branch history. Bind the update to its exact accepted PR head, final merge and relevant parents/tree. Missing, ambiguous, inconsistent or unsupported evidence refuses. Establish the narrow proof before broadening accepted update shapes. Never infer authority from commit-message text or caller assertions.

The entire candidate DAG is still checked; direct and side-branch commits retain the existing identity checks. Both publication and pre-push use the same guard. No trust-baseline changes, forced history repair, hook bypass, credential exposure, or weakened existing merge checks.

## Acceptance and evidence

A synthetic reproduction of the ESS update-branch/final-merge graph fails before and passes after the repair. Negative cases cover forged actor/signature, wrong repository or PR, fork/nondefault/unmerged or ambiguous PR, parent/tree mismatch, unpublished updates, missing objects, and unsupported graph shapes. Independent adversarial review and guard-removal mutation evidence are required. Full cargo test --locked, cargo fmt --all --check, cargo clippy --all-targets --locked -- -D warnings must pass. Publish through existing bot/common-Gates paths and verify release artifacts before consumer adoption. Retry the original refused ESS publication only with the reviewed delivered tool.

## Scope

Cited: src/published_merge.rs contains the shared ancestry verifier. Cited: tests/published_merge.rs and tests/adversary_published_merge.rs exercise authenticated evidence through both adapters. Cited: src/hooks.rs and src/delivery.rs call the verifier; retain that shared path. Inferred: bounded release metadata changes to Cargo.toml, Cargo.lock and CHANGELOG.md will be needed to deliver the corrected tool.

## Planning compatibility

The installed AEP 0.68.0 refused aep.project/1. Its named migration verified all eight existing artifacts, fourteen transitions and thirteen evidence records against the old store. The Git planning scope is gates. Historical bodies and evidence are preserved, and the old journal remains in Git history. This compatibility prerequisite shares the same review branch.
