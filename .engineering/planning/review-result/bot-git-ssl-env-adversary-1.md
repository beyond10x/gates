---
format: aep.planning-md/3
id: review-result:bot-git-ssl-env-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: the bot''s Git takes no caller TLS setting'
relations:
- reviews: story:bot-git-ssl-env
revision: 1
---
verdict: NEEDS-CHANGE
cases: executed 4→11, red 5
origin: introduced 0, pre-existing 5, undecided 0

Unit diff 2570df0..f715c6d. Cases in `tests/adversary_bot_git_ssl_env.rs`.

- The caller's `GIT_SSL_*` variables and `SSLKEYLOGFILE` stayed out of the bot's push, fetch
  and delete-branch push, as the acceptance requires.
- Red: the repository's own configuration reached the bot's push. Five forms were found: a
  URL-scoped `http.https://github.com/.sslVerify=false`, the same through `include.path`,
  `http.sslCAInfo`, `http.sslCAPath`, and an `insteadOf` rewrite to plain HTTP. A URL-scoped
  key is more specific than the bot's `-c http.sslVerify=true`, so Git took the repository's
  value.
- Fixed in 5203e8b, merged 2ab2271. The bot reads the repository's configuration as data and
  sets every TLS key again through `GIT_CONFIG_COUNT`. GitHub URL rewrites are neutralised by a
  rules file read before the repository's, and a rewrite no key can name is refused.
- Held: a repository-wide `sslVerify=false`, through `include.path` or `includeIf`, does not
  win over the bot's `-c`.
