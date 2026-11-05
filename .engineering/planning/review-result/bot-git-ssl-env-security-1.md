---
format: aep.planning-md/3
id: review-result:bot-git-ssl-env-security-1
kind: review-result
status: active
title: 'Security review 1: the bot''s Git takes no caller TLS setting'
relations:
- reviews: story:bot-git-ssl-env
revision: 1
---
verdict: INFEASIBLE, 3 red on repository configuration, acceptance met
cases: executed 4→7, red 3
origin: introduced 0, pre-existing 3, undecided 0

Unit diff 2570df0..f715c6d. Cases in `tests/security_bot_git_ssl_env.rs`.

- Red: a URL-scoped `sslVerify=false`, `http.sslCAInfo` and `http.sslCAPath` in the
  repository's own configuration reach the bot's push. A local TLS probe completed a
  handshake against an untrusted certificate. Fixed in 5203e8b, as in the adversary pass.
- Note: with `https_proxy=https://<user>@github.com`, Git asked the bot's credential helper for
  the proxy's credential. Fixed in 5203e8b: the helper answers only `protocol=https`,
  `host=github.com` with a path and no `username`.
- Note: the ci fetch kept the caller's `GIT_SSL_*` variables. Fixed in 5203e8b.
- Checked after the fix: a bot push from an SSH origin, in both
  `git@github.com:<owner>/<repo>.git` and `ssh://git@github.com/<owner>/<repo>.git` form,
  still gets the credential (`a_bot_push_from_an_ssh_origin_still_gets_the_credential`,
  c4804ed). A dry-run push with the App token from both forms was authenticated.
- Held: no environment variable and no global or system configuration turns TLS verification
  off or points it at another CA, and no TLS secret or token is written to disk or trace.
- Left outside the story: the ci fetch still inherits `GIT_CONFIG_PARAMETERS` and
  `GIT_TRACE2_*`, and the helper answers for any repository on github.com.
