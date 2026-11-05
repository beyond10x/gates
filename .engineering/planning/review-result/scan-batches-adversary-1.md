---
format: aep.planning-md/3
id: review-result:scan-batches-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: bounded scan batches'
relations:
- reviews: story:scan-bounded-batches
revision: 1
---
verdict: INFEASIBLE, 1 warning
cases: executed 77→90, red 1
origin: introduced 1, pre-existing 0, undecided 0

Unit diff c7343c2..645c070, attacked at 96d0ba0. Cases in `tests/adversary_scan_batches.rs`.

- Finding (warning, inside the acceptance, introduced): a predecessor read lazily was
  checked by its length only, so a same-length blob swapped between build and scan changed
  the inherited lines and hid an introduced line while a receipt was signed
  (`a_baseline_predecessor_swapped_between_build_and_scan_refuses`). Reach: a write to the
  object store during one gates process. Fixed in fc66ab6: the build binds each predecessor's
  SHA-256 and every late read refuses other bytes; the case is green and committed.
- Held (12 regression cases): own-object and predecessor swaps and removals refuse; replace
  refs change nothing; five versions of one file across batches keep their predecessors;
  batch edges at the limit; finding order and counts equal an unbatched run; ancestor reuse
  scans exactly the uncovered commits with a byte-equal receipt; staged and historical keep
  inheritance; `with_batch_limit` refuses 0 and values above the limit.
- Outside the acceptance: `ci` prints the batch count as `scanner_invocations=`; a commit or
  tag object between 256 and 512 MiB, admitted before, is now refused.
