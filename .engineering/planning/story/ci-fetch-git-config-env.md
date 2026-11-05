---
format: aep.planning-md/3
id: story:ci-fetch-git-config-env
kind: story
status: draft
title: Run the ci fetch without the caller's Git configuration and trace variables
tags:
- from-finding
relations:
- informed_by: review-result:bot-git-ssl-env-security-1
revision: 1
---
## Problem

Found by `review-result:bot-git-ssl-env-security-1`. The finding is pre-existing and lies outside that unit's diff. The `ci` fetch, which carries the workflow token, still inherits two groups of the caller's variables:

- `GIT_CONFIG_PARAMETERS`, for example a URL-scoped `http.https://github.com/.sslVerify=false`.
- `GIT_TRACE2_ENV_VARS` and `GIT_TRACE2_CONFIG_PARAMS`, which can probably write `GITHUB_TOKEN` or the auth header into a trace. This is inferred and not tested.

`tests/adversary_ci_fetch.rs` uses `GIT_CONFIG_PARAMETERS` to force protocol v0, so that test has to move to another route first.

## Proposal

Run the ci fetch with the same environment rules as `bot_command`:

- drop `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_COUNT` and the `GIT_TRACE2_*` variables;
- override the TLS keys the repository sets.

Move the protocol-v0 case in `adversary_ci_fetch` to a `-c` the test owns.

## Acceptance

Tests:

- a ci fetch with a caller `GIT_CONFIG_PARAMETERS` that sets a URL-scoped `sslVerify=false` resolves `sslVerify=true` for GitHub;
- a caller `GIT_TRACE2_ENV_VARS=GITHUB_TOKEN` writes no byte of the token into the trace;
- `adversary_ci_fetch` keeps its 10 cases green.
