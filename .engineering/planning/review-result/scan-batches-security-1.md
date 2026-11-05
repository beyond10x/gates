---
format: aep.planning-md/3
id: review-result:scan-batches-security-1
kind: review-result
status: active
title: 'Security review 1: bounded scan batches'
relations:
- reviews: story:scan-bounded-batches
revision: 1
---
verdict: nothing found
cases: executed 102→109, red 0

Unit diff c7343c2..645c070 plus fc66ab6, reviewed at d0e0e46. Cases in
`tests/security_scan_batches.rs` (committed in 68fd70f).

- Every unit of every batch reaches the private rules and the secret scanner
  (`src/git.rs:246-274`, `src/scan.rs:565-643`).
- A scanner failure at any batch, or an object removed after the build, refuses `check`,
  `check_reusing` and `reuse_or_scan`; nothing is signed.
- `objects_digest` is built from the bound digests and every late read goes through `bound`.
- Peak resident memory growth on a 26.2 MB candidate with 1 MiB batches stayed under 190 KB
  for build, scan, check, reuse, ci, staged and historical; the all-bytes control grew 24.5 MB.
- The batch limit is crate-private and can only be lowered by a library constructor no CLI
  or environment reaches; the per-blob limit still refuses; candidate gitleaks configuration,
  ignore files and inline allow comments change nothing.
- Outside the diff, pre-existing: `Git::read` and `tree` read all output before the size
  check, the commit-msg hook reads its file unbounded, and a non-Gitleaks scanner returning an
  out-of-range unit index panics (`src/scan.rs:644`).
