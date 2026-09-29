---
format: aep.planning-md/1
id: review-result:security-review-ancestor-receipt-reuse
kind: review-result
status: active
title: 'Security review: ancestor receipt reuse and batched reads'
relations:
- reviews: story:ancestor-receipt-reuse
revision: 1
---
## Verdict

Holds. No path found by which unscanned content obtains a signed receipt, and no weakened
guarantee. Five cases added to `tests/security.rs`, all green; two of them catch mutants the
existing suite let through. One integrity note, infeasible in practice, fixed by the coordinator.

```
unit: b10x-gates ancestor receipt reuse + batched object reads, f3d6a2c plus the added cases
verdict: CONFIRMED (2 suite gaps, now covered; 0 defects that let unscanned content through)
cases: executed 128→133, red 0
origin: introduced 3 / pre-existing 0 / undecided 0
```

## Cases added

- `review_a_signed_ancestor_receipt_claiming_more_commits_than_git_shows_is_not_trusted`: catches the
  mutant that takes the covered set from the receipt's claim instead of the range Git proves now.
- `review_a_forbidden_term_on_an_uncovered_merged_side_branch_refuses_signing`
- `review_a_forbidden_tag_message_refuses_signing_when_every_commit_is_covered`
- `review_check_scans_despite_a_stale_exact_receipt_planted_in_the_hook_directory`: catches the
  mutant that reuses an exact-head receipt from the hooks directory signed under an older policy.
- `review_blob_bytes_that_look_like_batch_protocol_survive_the_stream_exactly`

## Reviewed and cleared

Receipts planted from another clone or repository or signed under an older policy; history
rewritten below the ancestor (receipt range compared with the range Git computes now; all commands
run with `--no-replace-objects`; shallow repositories and grafts refused at open); same commit id
with other content (object digest recomputed); merges (set difference scans second-parent
commits); per-unit composition of scanner results; reuse of already-read units; size limits (the
full candidate is still built, 512 MB total unchanged); tags; receipt/Git read races; `verify`,
`publish` and `ci` unchanged; batch-stream refusals for oversized, missing, non-blob and
invalid-id reads and submodule entries.

```findings
- file: src/evidence.rs
  line: 233
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: no pre-existing test failed when the covered set was taken from the receipt's claim instead of the range Git proves now; the added overclaim case now catches it
- file: src/main.rs
  line: 442
  category: mutant
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: no pre-existing test failed when check reused a stale exact-head receipt from the hooks directory, a state every policy update produces; the added CLI case now catches it
- file: src/git.rs
  line: 163
  category: integrity
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: a contents header that disagrees with info is refused with the stream marked in place while the blob bytes are still unread, which contradicts the promise that a stream that loses its place refuses every later read
```
