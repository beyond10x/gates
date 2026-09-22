---
format: aep.planning-md/1
id: task:verify-published-bot-merge-ancestry
kind: task
status: implemented
title: Verify published App merge ancestry without weakening direct delivery
relations:
- derived_from: story:public-shared-gates
- derived_from: story:published-merge-delivery
revision: 5
---
## Problem and authority

EKR's bot-created pull-request merge 250aecaa0d3598a6354d22cd7a0f86b491468424
is already published. Common scanning signs the new candidate successfully, but
publish and pre-push run exact direct-bot committer checks across every ancestor
since adoption, including that GitHub-created merge. Publication therefore fails.

The workspace and Atlas AGENTS explicitly allow an App-authorized GitHub merge
after exact branch authority, App merge action and candidate-tree verification.
Implement that boundary in Gates, retaining strict exact bot identity for every
direct commit and keeping the adoption baseline and all scanning unchanged.

## Contract

Only an already published, exact bot-authored and GitHub-signed two-parent merge
may substitute authenticated remote evidence for an exact bot committer.
Proof comes from authenticated GitHub API reads, never candidate files, local
remote-tracking refs, commit-message claims or caller-provided exemptions.

Verify repository full name and numeric identity against trusted policy, public
visibility and exact App-only branch authority for all branches. Missing/redacted/
ambiguous protection evidence refuses. Verify exact commit SHA, bot author account
and raw identity, web-flow account and exact GitHub committer, valid verified
signature; a unique merged same-repository PR into the default branch; merged_by
the exact organization bot; merge SHA and PR head; both local parent identities;
first parent is ancestor of PR head; and merge tree equals PR head tree. Check
the merge is reachable from the current authenticated default-branch SHA.
Every other reachable candidate commit retains exact direct-bot author/committer
checks. Nested historical merges each need their own independent proof.

Apply one shared verifier in publish and pre-push. Commit-time strict checks stay
unchanged. Do not advance policy baseline, rewrite source history, relax branch
protection, bypass hooks or copy an Atlas dependency into Gates. Atlas's existing
source-authority implementation is a read-only reference.

## Acceptance

Synthetic Git objects and injected authenticated-read fixtures exercise valid
historical merge and refusal for forged identity/signature, wrong repo/App/PR,
fork, non-default target, unmerged/ambiguous/missing PR, missing/redacted/widened
authority, changed candidate tree, stale first-parent basis, missing objects,
unpublished/local-only merge and bad direct or side-branch commit.
Test both publication call paths bind the same guard; removing each critical
proof check must cause a relevant regression. No network credentials in fixtures.

Run complete Gates test/fmt/clippy, independent adversarial review and mutation
evidence, then required source CI. Release and verify binary/checksum assets before
adopting a consumer or its pinned coordinated hooks. Existing check semantics and
zero-scan receipt reuse remain intact. This is a necessary bounded dependency
repair under the operator's approved EKR completion/publication instruction.

## Published and adopted

The reviewed implementation is on main at 9466d1fe3aca3eeeace91547496fef5a46c21503,
through https://github.com/beyond10x/gates/pull/16. Required correctness and shared
checks pass for the candidate, main and annotated release tag. The published release
is https://github.com/beyond10x/gates/releases/tag/0.1.6, authored by the organization
bot. The downloaded static binary and checksum asset match the built artifacts;
the binary reports the release version and its SHA-256 is
f4f4974cdd13b896e875574f159d6c07fa7ba9a143577a9e3c36c5695fbe2d51.

Adoption updated the CLI and coordinated hooks for Gates, Eventlog and EKR while
preserving prior hook-chain and retirement digests. Other repository hooks are
unchanged. EKR's actual seed publication then passed both publication and pre-push
verification over the historical GitHub merge. Its required correctness and
shared checks passed, and https://github.com/beyond10x/epistemic-knowledge-runtime/pull/8
is merged at a4b21d54e3838efbf924cb60666073b2bf493b67. This closes the reproduced
delivery blocker without moving the adoption baseline or weakening branch rules.

Retained evidence: release-published.json, release-verified/, hook-chain before
and after files, and the consumer publication receipt in the completion run's
private scratch. Source review and mutation evidence remain linked above.
