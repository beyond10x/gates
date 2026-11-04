---
format: aep.planning-md/3
id: story:scan-bounded-batches
kind: story
status: active
title: Scan a candidate in bounded batches so its total size is no limit
summary: A main far past its adoption baseline exceeds any fixed candidate total; read and scan the units in batches of at most 256 MiB instead.
scope:
- confidence: inferred
  path: README.md
- confidence: inferred
  path: src/evidence.rs
- confidence: inferred
  path: src/git.rs
- confidence: inferred
  path: src/scan.rs
- confidence: inferred
  path: tests/scan_batches.rs
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-11-04T12:07:01Z", actor: "human:timo", revision: 4}
- {from: "proposed", to: "active", at: "2026-11-04T12:07:01Z", actor: "human:timo", revision: 5}
---
## Problem

`b10x-gates check` and `ci` read every changed file version of every commit from the
repository's adoption baseline to the head into memory, and refuse the candidate when the total
passes a fixed cap (`MAX_TOTAL` in `src/git.rs`, checked per commit in `units` and over the whole
candidate in `build`). A repository whose main grows past its baseline eventually exceeds any
fixed cap, and from then on every pull request fails `common / Security and privacy` with
`candidate exceeds scan limit`. Squashing a pull request does not help, because the commits on
main are in range too.

Raising the cap only moves the cliff: on 2026-10-02 the ESS pull request 359 was refused by
scanner 0.1.8, which already allowed 512 MiB (run 36958313884, about 3.5 min into `ci`). Only
moving the baseline in the private policy cleared it.

## Proposal

- A candidate keeps, per unit, what identifies its bytes (location, blob id, predecessor blob
  id, workflow flag, digest, length) and reads the bytes when the unit's batch is scanned.
- Units are scanned in batches whose bytes, predecessors included, stay at or under 256 MiB;
  each batch runs the private rules and the secret scanner once, and the reports are merged in
  unit order. A single blob over the per-blob limit is still refused.
- The refusal of a candidate by its total size is removed. Nothing else changes: the candidate
  binding, `objects_digest`, the receipt shape, the result roster and the findings of a
  candidate under the old cap are the same as before.
- Receipt reuse (`candidate_from`, ancestor receipts) keeps working on the same units.

## Acceptance

`tests/scan_batches.rs`, with a batch limit lowered for the test through a library constructor
that is not reachable from the command line:

- `candidate_over_the_old_cap_is_admitted`: a candidate of more than three batches is scanned
  and receives a receipt.
- `finding_in_the_last_batch_is_refused`: a forbidden literal planted only in the last batch is
  reported; the test fails when the last batch is dropped (mutation recorded).
- `no_batch_exceeds_the_limit`: a counting scanner sees no batch over the limit.
- `small_candidate_receipt_unchanged`: for a candidate inside one batch the receipt payload and
  `objects_digest` equal those of an unbatched scan.
- `oversized_blob_still_refused`: one blob over the per-blob limit is refused as before.

README states the batch limit instead of the old total limit.
