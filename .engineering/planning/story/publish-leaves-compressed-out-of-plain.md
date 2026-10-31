---
format: aep.planning-md/3
id: story:publish-leaves-compressed-out-of-plain
kind: story
status: implemented
title: Leave compressed repositories out of the organization plain policy secret
summary: policy publish leaves the exceptions of compressed repositories out of the organization's plain B10X_GATES_POLICY, as it does for sliced ones
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-31T13:41:20Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-31T13:41:20Z", actor: "human:timo", revision: 3}
- {from: "active", to: "implemented", at: "2026-10-31T13:43:04Z", actor: "human:timo", revision: 4, decided_on: {"asserted":{"test_result":1}}}
---
## Problem

`b10x-gates policy publish` leaves the exceptions of `sliced` repositories out of the
organization's plain `B10X_GATES_POLICY` secret, but not those of `compressed` ones. One
repository's plain slice reached 51,475 bytes, over the 48,000-byte limit, so no policy change
published. Moving it from `sliced` to `compressed` put its exceptions back into the
organization's plain value, which then measured 71,288 bytes and was refused as well.

## Proposal

- The organization's plain secret leaves out the exceptions of every repository listed under
  `sliced` or `compressed`. A `compressed` repository reads `B10X_GATES_POLICY_GZ`, which
  holds the whole policy, so it needs no plain value.
- README and the `gates.delivery.PublishPolicy` comment say so.

## Acceptance

- `tests/policy_publish.rs`: `compressed_repositories_leave_the_organization_plain_secret`
  (a policy whose `compressed` repository's exceptions alone exceed the limit publishes; the
  organization's plain value holds no exception of that repository; that repository gets the
  whole compressed policy and no plain repository secret). It failed before the change with
  the organization plain value at 109,321 bytes.
- Moving a repository in the operator's `publish.json` and running `--apply` stay with the
  steward after the release; this story does neither.
