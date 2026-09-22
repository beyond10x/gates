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
