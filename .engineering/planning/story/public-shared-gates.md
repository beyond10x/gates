---
format: aep.planning-md/1
id: story:public-shared-gates
kind: story
status: active
title: Publish independent common gates and adopt Eventlog, ESS and AEP
scope:
- confidence: cited
  path: .github/workflows/
- confidence: cited
  path: .github/workflows/shared-gates.yml
- confidence: cited
  path: CHANGELOG.md
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: cited
  path: README.md
- confidence: cited
  path: docs/adoption.md
- confidence: cited
  path: ess/
- confidence: cited
  path: src/
- confidence: cited
  path: tests/
revision: 5
---
## Intent and authority

Implement the operator-approved Public shared gates, independent of Atlas plan. This is an interactive run. The new repository contains only its bot-created initial README and license (reverse scan/history on 2026-09-10); there is no legacy backlog to migrate. Atlas task:eventlog-source-gate-reuse coordinates authority migration; Eventlog story:atlas-source-gate-reuse owns the retained consumer draft.

## Acceptance

Publish a gated Rust CLI and immutable reusable GitHub workflow before pinning Eventlog, then ESS and AEP. Enforce common secret/privacy checks over staged data and every new outgoing commit, including names, metadata and tags. Keep private policy out of public source and outputs. Verify standard signatures bound to repository numeric identity, exact objects/range, pinned scanner and both policy digests; reject incomplete results and prove zero scanner invocations on valid reuse. Use protected local policy/signers and selected-repository secrets. Fork candidates are Git data only. Preserve coordinated existing hooks and the bot identity, retain evidence across delivery retries, and demonstrate operation with Atlas unavailable.

Enable shared integration checks and supported GitHub secret scanning/push protection. Record explicit adoption baselines and historical findings separately without rewriting history. Retain consumer correctness, release checks and artifacts; expensive repository-specific proof reuse and downstream releases are excluded. Retain Eventlog cache/cancellation independently. Update organizational authority and obsolete brand-exemption guidance. Complete or explicitly hand off managed worktree cleanup.

## Typed contract and scope

The immutable signed receipt is modeled in ess/system.yaml and ess/domains/evidence.yaml (validated by the installed ESS 0.9.2 `ess validate` command). Rust serde types define the strict v1 wire envelope and result roster. Scope: src/, tests/, ess/, .github/workflows/, README.md, CHANGELOG.md and Cargo manifests in Gates; consumer workflows and AGENTS.md; Atlas authority, activation and planning records. One story owns Gates implementation; no story decomposition or parallel scheduling is performed, so decomposition critics are inapplicable.

## Required verification

Staged versus unstaged bytes; intermediate commits; commit/tag messages and identities; bare Linux/macOS/Windows homes and portable placeholders; ignore/comment attacks; redaction; hostile fork files; receipt tampering, wrong repository/key/policy and missing result; zero scanner reuse; hooks and bot publish with Atlas unavailable; exact public release assets and pinned pilot enforcement.
