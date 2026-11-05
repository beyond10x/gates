---
format: aep.planning-md/3
id: review-result:token-env-error-value-security-1
kind: review-result
status: active
title: 'Security review 1: secret variable errors withhold the value'
relations:
- reviews: story:token-env-error-value
revision: 1
---
verdict: INFEASIBLE, 3 red on naming the variable, no value leaked
cases: executed 8→11, red 3
origin: introduced 0, pre-existing 0, undecided 3

Unit diff 2570df0..542ec39. Cases in `tests/security_token_env_error_value.rs`, 0405e66.

- Red: an empty `B10X_BOT_TOKEN` was refused as "GitHub token unavailable", which does not
  name the variable.
- Red: an empty `GITHUB_TOKEN` passed the pre-fetch read, so `ci` read the event and fetched
  without a credential, contrary to the comment at the read.
- Red: the push-evidence refusal's top-level line, the only line `main` and a refused evidence
  read print, did not name `B10X_BOT_TOKEN`.
- No shipped workflow was shown to reach any of the three: `common.yml` always passes
  `github.token`, and `bot_command` always sets a non-empty token.
- Fixed in the wave: `secret_env::required` refuses an empty value naming the variable, and
  the push-evidence error carries its reason in the top-level text.
- Held:
  - No secret value reaches a child process's argv.
  - `Github` has no `Debug`.
  - Every policy parse error is a fixed string.
  - A non-Unicode policy variable is refused before any decoding.
