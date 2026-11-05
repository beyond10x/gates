---
format: aep.planning-md/3
id: review-result:token-env-error-value-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: secret variable errors withhold the value'
relations:
- reviews: story:token-env-error-value
revision: 1
---
verdict: nothing found
cases: executed 4→4, red 0
origin: introduced 0, pre-existing 0, undecided 0

Unit diff 2570df0..542ec39. Cases in `tests/adversary_token_env_error_value.rs`, b811650.

- Held: for each case below, no 4-byte window of the value appeared in `{}`, `{:#}`, `{:?}`
  or the binary's output.
  - An invalid compressed policy (`B10X_GATES_POLICY_GZ`): bad base64, non-gzip data, a
    trailing member, a truncated stream and 9 invalid contents.
  - The same 9 contents in `B10X_GATES_POLICY_JSON`.
  - A token with a newline, CRLF, DEL or NUL.
  - A 401 answer whose body echoes the `Authorization` header.
- Held: every secret read in `src/` goes through `src/secret_env.rs`.
- Note, outside acceptance: an empty `GITHUB_TOKEN` or `B10X_BOT_TOKEN` is refused as "GitHub
  token unavailable" without naming the variable.
- Note: `PushEvidence` is now `pub` and `#[doc(hidden)]` so that tests can reach it.
