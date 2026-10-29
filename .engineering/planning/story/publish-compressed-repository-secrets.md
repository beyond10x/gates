---
format: aep.planning-md/3
id: story:publish-compressed-repository-secrets
kind: story
status: active
title: Publish the compressed policy to repository secrets of private repositories
summary: policy publish writes B10X_GATES_POLICY_GZ as a repository secret for each repository the targets list under compressed
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-29T09:22:31Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-29T09:22:31Z", actor: "human:timo", revision: 4}
---
## Problem

Private repositories do not receive the organization secret `B10X_GATES_POLICY_GZ`, so each
needs a repository secret of its own. The targets file of `b10x-gates policy publish` has no
field for them: their copies are refreshed by hand and go stale behind the policy, and a
commit relying on a newer exception stays red on `common / Security and privacy` there.

## Proposal

- `Targets` gains `compressed`: a list of `owner/repo`, serde-default empty, so a targets file
  without it still parses.
- For each listed repository, publish writes the whole policy as the repository secret
  `B10X_GATES_POLICY_GZ`, gzip -9 then base64, the same value as the organization secret and
  the encoding `ci` reads. The dry run lists each such target and its size; `--apply` writes
  it with `gh secret set --repo`, the value on standard input, and reads it back with
  `gh secret list --repo` before the marker moves.
- A listed repository must be a valid `owner/repo`, enrolled in the policy, and listed once;
  otherwise nothing is published.
- Spec: the comment of `gates.delivery.PublishPolicy` names the repository targets.

## Acceptance

- `tests/policy_publish.rs`: `compressed_targets_parse_and_default` (the field parses, and a
  targets file without it plans no repository secret), `compressed_repositories_planned` (the
  dry run names each repository secret and writes nothing),
  `compressed_repositories_published_and_read_back` (`--apply` writes the whole policy to each
  listed repository, reads each scope back, then moves the marker),
  `compressed_repository_not_read_back_keeps_the_marker`, and
  `compressed_repository_unenrolled_refused` / `compressed_repository_duplicate_refused` /
  `compressed_repository_invalid_refused`.
- Adding repositories to the operator's `publish.json` and running `--apply` is the steward's,
  after the release; this story does neither.
