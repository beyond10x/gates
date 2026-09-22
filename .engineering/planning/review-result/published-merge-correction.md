---
format: aep.planning-md/1
id: review-result:published-merge-correction
kind: review-result
status: active
title: Independent proof-list admission correction review
relations:
- reviews: story:published-merge-delivery
revision: 1
---
unit: story:published-merge-delivery, 270c290 plus coordinator list-admission correction, version 0.1.6
verdict: nothing found in the bounded re-review; original finding resolved
cases: executed 6→6 in the unchanged targeted review lane, red 0
origin: introduced 0 / pre-existing 0 / undecided 0
wrote-outside-worktree: assigned scratch report/log/manifest and existing assigned compiler target
needs-coordinator: coordinator mutation and full gate remain

```text
git --no-pager diff --stat
 .engineering/planning/journal.jsonl                |  3 +++
 .../planning/story/published-merge-delivery.md     | 12 ++++++---
 .engineering/waves/published-merge-delivery.md     | 14 ++++++++--
 CHANGELOG.md                                      |  6 +++++
 Cargo.lock                                        |  2 +-
 Cargo.toml                                        |  2 +-
 src/delivery.rs                                   | 31 ++++++++++++++++++++++
 src/git.rs                                        | 19 ++++++++-----
 src/hooks.rs                                      | 19 ++++++++++++-
 src/lib.rs                                        |  1 +
 src/main.rs                                       |  8 +++++-
 11 files changed, 101 insertions(+), 16 deletions(-)
```

Owners: the coordinator owns the production list-admission correction, version/release files and concurrent disjoint planning/report work. The original implementor owns the underlying stable source and original tests. This reviewer owns the earlier adversary test file and current scratch outputs. No repository file was edited by this reviewer in the re-review. The whole-tree diff above belongs to those other owners and predates or accompanies this explicitly shared review; the review-owned repository delta is empty. The original source finding is handed back as resolved by the coordinator, without revising its undecided historical origin.

The unchanged adversary file hash matched the dispatched value both before and after execution:

```text
96dbdddf4a2c162d70cdd1e46af6759184e39dbebbfebd1f55df4ce65fcac62b  tests/adversary_published_merge.rs
```

No test was added, renamed, deleted, weakened or skipped in this pass. The original single-case behavioral red remains retained in proof-list-first.log and adversary-report.md.

The correction validates every list entry before the respective uniqueness filter. Ruleset entries must carry a positive numeric identity and a nonempty string name. Associated PR entries must carry a positive numeric number and an explicitly present merge_commit_sha that is either null or a valid object id. Non-object entries cannot satisfy these accesses. A missing/null/wrongly typed name, a missing PR discriminator, or the wrong discriminator type now refuses rather than disappearing as an unrelated entry.

This is validation of the fields necessary to select and identify proof, not a claim that every GitHub response property is schema-validated. Supported unrelated entries remain admissible. An explicit null merge SHA is preserved as a nonmatching supported value; it is not confused with absence. Existing detailed authority/commit/PR checks still decide the selected proof after uniqueness, and the code still consumes the complete paginated lists first. No payload normalization, candidate execution, local-ref exemption or persistent evidence cache was added.

| Original finding/control | Observed result |
|---|---|
| G1: malformed entries discarded before proof uniqueness | Resolved. All twelve malformed list/adaptor observations now refuse in the unchanged regression. |
| Legitimate unrelated ruleset and explicit-null unmerged PR | Passes; correction preserves the documented nullable distinction. |
| Later non-bot commit, including side ancestry | Refuses through both adapters. |
| Local replacement ref over a bad commit | Refuses through both adapters. |
| Changed authority after an earlier valid call | Refuses rather than retaining the earlier authority. |
| Duplicate qualifying proof on a later page | Refuses; complete unrelated first-page control still passes. |

Execution used the assigned target and scratch, CARGO_BUILD_JOBS=2, and the existing pinned Gitleaks path. Free space was measured at 16 GB immediately before cargo, above the 10 GB floor.

Command:
`cargo test --locked --test adversary_published_merge -- --nocapture`

Exit 0; six executed, six passed, zero ignored, zero filtered:

```text
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.07s
     Running tests/adversary_published_merge.rs (<cache>/b10x-target/ekr-gates-published-ancestry-20260922/debug/deps/adversary_published_merge-8100e32f9b880ddc)

running 6 tests
test adversary_unrelated_rules_and_explicit_null_unmerged_pr_remain_valid ... ok
test adversary_remote_authority_is_not_reused_across_verification_calls ... ok
test adversary_local_replacement_cannot_hide_a_nonbot_commit ... ok
test adversary_duplicate_proof_on_later_page_is_not_ignored ... ok
test adversary_published_merge_does_not_excuse_a_later_nonbot_committer ... ok
test adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.28s


```

The coordinator's correction-targeted.log was read and reports 6 + 61 = 67 passing cases. Those 61 original implementation cases were not rerun by this reviewer in this bounded pass. This pass also ran git diff --check, exit 0. No wider suite, extra mutation or live publication was performed; coordinator mutation and the full gate remain separate work. The seven previously ignored security cases were not changed or represented as executed here.

Outside writes in this pass:
- <cache>/ekr-completion-20260922/gates-ancestry/adversary/correction-six.log
- <cache>/ekr-completion-20260922/gates-ancestry/adversary/correction-review.md
- <cache>/ekr-completion-20260922/gates-ancestry/adversary/correction-outside-paths.txt
- Existing compiler target <cache>/b10x-target/ekr-gates-published-ancestry-20260922

Temporary synthetic fixtures used the assigned scratch/TMPDIR and normal lifetime cleanup. Exact local paths are retained in correction-outside-paths.txt, not this public-safe report. The reviewer's own managed lease, codex-ekr-gates-correction-review, is released at handback. No compiler remains running; source and tests are stable. No production/AEP change, commit, publication, live store access or managed-tree cleanup occurred.

```findings
[]
```

