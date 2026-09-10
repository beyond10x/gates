---
format: aep.planning-md/1
id: task:automation-authorship-ess-release
kind: task
status: implemented
title: Enforce automation authorship and release the repaired ESS pull requests
relations:
- derived_from: story:public-shared-gates
revision: 6
---
## Context

The operator requested repair of both open ESS pull requests, rewriting incorrect commits, common authorship enforcement for all Gates adopters, integration with no outstanding ESS pull requests, and a new verified ESS release. Local pre-push verifies bot identities, but shared CI and signed receipt admission currently do not enforce an author allowlist.

## Acceptance

All common Gates candidate paths reject any new commit whose raw author is outside the exact bot and GitHub Actions identities, regression and mutation checks demonstrate enforcement, every enrolled adopter uses the verified release, and the repaired ESS changes are integrated with zero open pull requests and a verified new release including required artifacts.

## Scope and order

Audit exact ESS candidate histories and preserve both changes; repair conflicts and rewrite improper identities or public commit provenance. Implement the common rule in Gates, invalidate older evidence by policy/version, verify and release Gates, then update every existing shared-workflow adopter. Direct source delivery retains the exact organization bot author and committer requirement. Historical adoption baselines remain separate from candidate admission. Verify complete ESS gates at the merged release commit, publish an annotated version tag, and verify checks, release and archives. Documentation delivery remains asynchronous.

Planning critics are skipped because this is one task with no child decomposition. The existing shared Gates story owns the coordinated adoption boundary.

## Verified implementation and rollout

Gates 0.1.1 is published at commit 0b0220a36e37b5899e9b298c7b42a7daf6e83850. Its exact tag checks passed; the downloaded static Linux binary matched SHA256 d9f1566dfd2b321d2f9f3722fd3f19bca6e23ee8e950ea2a6cdd0901a848a7fb and reported 0.1.1. Full Rust checks passed. Removing candidate author admission caused the human/spoofed/duplicate and intermediate/merge regressions to fail; removing local hook identity admission caused the installed-hook regression to fail. Restoring each guard passed.

All four adopters now pin workflow 547c6bc58d734e679f21bdeeb365f7dcc88059b1. Gates, AEP, Eventlog and ESS main shared runs downloaded the verified release and reported evidence_reused=true with scanner_invocations=0. Coordinated local hooks also use 0.1.1. Repository correctness checks remained required. Eventlog's first capacity witness exceeded its 2-second maximum by about 10 milliseconds with zero correctness violations; an unchanged rerun and the subsequent main proof passed.

Both ESS branches were rewritten with explicit force-with-lease. The original personal identity was the creator of PR 24; its Git author and committer were already the bot. Its commit was replayed with public provenance and the xattr allowance narrowed to exact platform access labels. Bot-owned PR 27 replaced it and merged after every required check. PR 25 was resolved, updated for 0.22.2, gated and merged. ESS has no open PRs. The annotated bot tag 0.22.2 names merged commit 6b666e58f2e87dd8798d27f935e9a012203296a3; release run 34522479738 completed successfully. GitHub Actions published the non-draft release with all four native archives and SHA256SUMS. Downloaded archives passed SHA256SUMS and GitHub asset-digest checks; each contained exactly the expected binary, license and readme. The downloaded Linux x86_64 binary reported ess 0.22.2 and passed --help.

## Preserved existing ESS findings

The exact release candidate passed task check SKIP_CONSUMER_CHECKS=true, the established CI/release mode, and task site-build including the browser lab; both native macOS witnesses passed. Full consumer qualification remains unproven: earlier at_most_once work left unclassified entries and 885 stale/unaccounted cells. The two new xattr helpers were classified explicitly, while the accepted initial baseline remains byte-for-byte unchanged. Its semantic eligibility was not transferred to changed obligations. The existing qualify-initial-consumer-baseline epic retains that follow-up scope.

Release-status preflight also found the historical 0.21.0 tag without a GitHub Release. The historical tag was neither deleted nor represented as passing. The final task release-status confirms 0.22.2 is tagged and published; its nonzero result now names only the historical 0.21.0 gap. Exact 0.22.2 publication, required release checks and artifact verification are complete. Documentation publication is asynchronous.
