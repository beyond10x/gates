---
format: aep.planning-md/3
id: approval-record:common-scanner-pin-0-1-24-approval
kind: approval-record
status: draft
title: Orchestrator approved moving the common workflow scanner pin to 0.1.24
revision: 2
---
## Who decided

The monitoring session `b10x-chef-orchestrator`, under the grant in the workspace instructions
(class C: a dependency upgrade, PR and merge through the bot). Its message to the `gates`
session on 2026-10-29 (item D192):

> move the scanner pin in gates/.github/workflows/common.yml from 0.1.21 (line 29, sha256 on
> line 31, last moved in 09654b1) to 0.1.24, with the sha256 from the 0.1.24 SHA256SUMS.

> if any consumer gets a new finding or a new refusal, stop: don't open the PR

## Decided

Move the pin, after `ci` of 0.1.21 and 0.1.24, run as `common.yml` runs it with the policy
at `gates-policy` `5d1005e`, gave the same result on atlas `f21587b2`, substrate `07396286`
and ess `d5c00e9c` (exit 0, no findings, full scan, no evidence reused). `src/git.rs`,
`src/scan.rs`, `src/evidence.rs` and `src/policy.rs` are identical between the two tags, so the
128 MiB blob and 512 MiB candidate limits are unchanged. No release: the reusable workflow is
consumed at a commit, and this repository's instructions name no release for a workflow
change.
