---
format: aep.planning-md/3
id: story:test-step-budget
kind: story
status: draft
title: Bring the test step under 120 s in one test binary that runs in the pool
summary: Whole suite measured at 127 s wall over 46 test binaries; 7 tests cannot find the pinned scanner on the build node
revision: 1
---
## Problem

The test step of this repository runs over the 120 s budget of the organization's rules ("Tests
stay fast"), and it cannot run complete through the shared build pool.

Measured 2026-11-24 on branch `fix/squash-merge-moved-base` (base `ba05649`), through the pool's
build node, with the pinned scanner named by `B10X_GATES_GITLEAKS`:

- `cargo test --locked` stopped at the 24th of 48 test targets after 90 s wall (271 passed,
  3 failed); the 22 remaining test binaries run with `--no-fail-fast` took 37 s wall (471 passed,
  4 failed). Together 127 s wall over the two commands, 742 passed, 7 failed, 21 ignored.
- Slowest binaries: `adversary_hex_paths` 43.9 s, `security_scan_batches` 27.5 s,
  `adversary_wrapped_lines` 24.9 s.
- `tests/` holds 46 integration-test files, each its own binary. The rule asks for one
  integration-test binary per crate (`tests/main.rs` with modules).
- The 7 failures (3 in `artifact`, 3 in `security`, 1 in `security_scan_batches`) each report
  `pinned Gitleaks binary unavailable` or `No such file or directory`: the tests run on the build
  node and the scanner path exists only on the workstation. The forge passes the same tests
  (`.github/workflows/quality.yml:31-32` sets `B10X_GATES_GITLEAKS` to a scanner it bootstraps).
  Not measured: whether the 7 fail the same way on `ba05649`.

## Contract

- The test step of `cargo run --locked -- gate` ends within 120 s wall and prints its ten slowest
  tests; a test over 60 s is killed and counts as failed.
- One integration-test binary (`tests/main.rs` with modules).
- The tests that need the pinned scanner find it wherever the pool runs them, or the step refuses
  before it starts and names what is missing. The local gate and the forge run the same tests.

## Acceptance

`slot cargo run --locked -- gate` on the workstation ends green within 120 s wall, with the same
passed count as the forge's `Gates correctness` run of the same commit.

## Scope

- `tests/*.rs` (46 files): cited.
- `src/main.rs` (`gate`): inferred.
- `.github/workflows/quality.yml`: cited.
