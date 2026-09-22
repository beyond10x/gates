---
format: aep.planning-md/1
id: story:published-merge-delivery
kind: story
status: active
title: Permit verified historical App merges in bot delivery
scope:
- confidence: cited
  path: CHANGELOG.md
- confidence: cited
  path: Cargo.lock
- confidence: cited
  path: Cargo.toml
- confidence: cited
  path: src/delivery.rs
- confidence: cited
  path: src/git.rs
- confidence: cited
  path: src/hooks.rs
- confidence: cited
  path: src/lib.rs
- confidence: cited
  path: src/main.rs
- confidence: cited
  path: src/published_merge.rs
- confidence: cited
  path: tests/adversary_published_merge.rs
- confidence: cited
  path: tests/published_merge.rs
- confidence: cited
  path: tests/security.rs
revision: 14
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

# Reviewed published-merge delivery candidate

The shared verifier proves historical App-created merge ancestry from authenticated
repository, branch-authority, commit and pull-request evidence. All direct commits
retain exact bot author and committer checks. Both publish and pre-push bind this
same verifier, and the verifier enumerates the complete candidate DAG itself.

Independent review found that malformed entries could be discarded before remote
proof-list uniqueness was established. The coordinator now validates every entry's
identity and discriminator before filtering. An explicitly null unmerged PR hash
remains supported. The adversary cases remain unchanged; the correction review
records their exact digest and passing observations.

Owners: implementor owns original Rust implementation; coordinator owns proof-list
correction, release metadata, integration and delivery. The independent review
and correction review retain their original findings and attribution.

The coordinator disabled the new ruleset-list entry check, causing the unchanged
adversary case to fail behaviorally with cargo exit 101. It observed
malformed entries accepted through both real adapters. Original source was restored
byte-for-byte before the final gate. Retained logs: coordinator-mutation.log and
correction-original.rs in the assigned unit scratch.

Final gate: cargo test --locked; cargo fmt --all --check;
cargo clippy --all-targets --locked -- -D warnings. Each exits zero.
Measured suite totals: 108 passed, 0 failed, 7 ignored. The ignored security cases predate this
unit and remain unchanged; no claim is made that they pass. The existing pinned
scanner supplies real scanner tests. The implementor report additionally records
its source and call-site mutation sweep, including the corrected masking fixture.

The release version is prepared in the manifest, lock and changelog. Required
remote source checks, annotated tag, static binary/checksum publication and download
verification remain pending. EKR consumer and coordinated-hook adoption follow
that evidence; no policy baseline or branch protection is changed to unblock it.
