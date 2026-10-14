---
format: aep.planning-md/3
id: story:ci-compressed-policy
kind: story
status: active
title: Read the CI policy from a compressed secret under the 48 KB limit
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-14T07:12:16Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-14T07:12:16Z", actor: "human:timo", revision: 3}
---
## Problem

The private policy reaches CI as a GitHub secret, and GitHub refuses a secret over 48 KB
("HTTP 422: Value is too large"). The policy is about 80 KB pretty-printed and about 64 KB in
compact JSON, so the organization secret `B10X_GATES_POLICY` can no longer be refreshed and
falls behind the policy; a repository whose commits rely on a newer exception stays red on
`common / Security and privacy`. Compressed with `gzip -9` and encoded as base64 the policy is
about 18 KB.

## Proposal

- `ci` reads the policy from `B10X_GATES_POLICY_GZ` (base64, then gunzip, then parse) when it
  is set and non-empty, else from `B10X_GATES_POLICY_JSON` exactly as before, else from the
  protected policy file. A set but undecodable compressed value is refused naming the
  variable, never a silent fallback; the decompressed policy is bounded at 4 MiB; diagnostics
  carry no byte of the value. ASCII whitespace in the value (a wrapped `base64`) is ignored.
- `.github/workflows/common.yml` declares the optional secret `B10X_GATES_POLICY_GZ`, passes it
  as the environment variable of that name, keeps `B10X_GATES_POLICY` optional and passed as
  `B10X_GATES_POLICY_JSON`, and downloads the release that reads it. Callers move to the new
  secret when they bump their pin of `common.yml`; callers on an older pin keep working.
- README and AGENTS.md say how the secret is produced (`gzip -9 -c policy.json | base64 -w0`)
  and that it must stay under 48 KB.
- Spec first: `gates.delivery.LoadCiPolicy` with the `PolicySource` type.

## Acceptance

- `tests/ci_policy.rs`: a gzip+base64 policy is accepted and equals the JSON parse
  (`loaded_from_compressed`); garbage, non-gzip, non-policy and over-bound values are refused
  naming `B10X_GATES_POLICY_GZ`; a broken compressed value beside a valid JSON one is refused
  (`compressed_undecodable_never_falls_back`); the JSON path is unchanged
  (`json_path_unchanged`); the binary refuses an undecodable value and reads a valid one before
  the event (`ci_refuses_undecodable_compressed_policy`,
  `ci_reads_compressed_policy_before_the_event`).

## Publishing the policy

- `b10x-gates policy publish` is the step that writes those secrets, from
  `origin/main:policy.json` of the policy repository only (fetched, read with `git show`).
  Dry run by default; `--apply` writes with `gh secret set` (value on standard input) and reads
  the names back with `gh secret list`; the targets (organization, plain sliced secrets for
  callers on older pins) come from a JSON file; any value of 48,000 bytes or more publishes
  nothing; a marker in Gates' state directory makes a repeat print `unchanged`, `--force`
  publishes anyway. Spec: `gates.delivery.PublishPolicy`.
- Acceptance: `tests/policy_publish.rs` with a fake `gh` on `PATH` (`planned_by_default`,
  `published_with_apply`, `only_origin_main_is_published`, `unchanged_publishes_nothing`,
  `forced_publishes_unchanged`, `oversized_publishes_nothing`, `compressed_only_targets`,
  `invalid_policy_publishes_nothing`, `write_failure_keeps_the_marker`,
  `missing_read_back_keeps_the_marker`).
