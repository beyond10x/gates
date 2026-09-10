---
format: aep.planning-md/1
id: task:automation-authorship-ess-release
kind: task
status: active
title: Enforce automation authorship and release the repaired ESS pull requests
relations:
- derived_from: story:public-shared-gates
revision: 3
---
## Context

The operator requested repair of both open ESS pull requests, rewriting incorrect commits, common authorship enforcement for all Gates adopters, integration with no outstanding ESS pull requests, and a new verified ESS release. Local pre-push verifies bot identities, but shared CI and signed receipt admission currently do not enforce an author allowlist.

## Acceptance

All common Gates candidate paths reject any new commit whose raw author is outside the exact bot and GitHub Actions identities, regression and mutation checks demonstrate enforcement, every enrolled adopter uses the verified release, and the repaired ESS changes are integrated with zero open pull requests and a verified new release including required artifacts.

## Scope and order

Audit exact ESS candidate histories and preserve both changes; repair conflicts and rewrite improper identities or public commit provenance. Implement the common rule in Gates, invalidate older evidence by policy/version, verify and release Gates, then update every existing shared-workflow adopter. Direct source delivery retains the exact organization bot author and committer requirement. Historical adoption baselines remain separate from candidate admission. Verify complete ESS gates at the merged release commit, publish an annotated version tag, and verify checks, release and archives. Documentation delivery remains asynchronous.

Planning critics are skipped because this is one task with no child decomposition. The existing shared Gates story owns the coordinated adoption boundary.
