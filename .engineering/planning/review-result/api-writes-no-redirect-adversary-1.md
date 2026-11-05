---
format: aep.planning-md/3
id: review-result:api-writes-no-redirect-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: API writes are never sent along a redirect'
relations:
- reviews: story:api-writes-no-redirect
revision: 1
---
verdict: nothing found
cases: executed 5→14, red 0
origin: introduced 0, pre-existing 0, undecided 0

Unit diff 57527c1..493ea00. Cases in `tests/adversary_api_writes_no_redirect.rs`, 9765af2.

- Held, writes: a POST, PUT, PATCH, DELETE or OPTIONS answered with any 3xx, with or without
  a `Location`, is sent once with its body unchanged and never re-sent. The refusal never
  shows the `Location`.
- Held, reads: a GET or HEAD is not followed on 300, 304, 305, 306, 309 or 399. A missing,
  empty, non-UTF-8 or non-ASCII `Location` is refused. Each of 33 `Location` forms that the
  URL parser would rewrite is refused, and the second host receives no request.
- Held, limits: 10 redirects are followed; a loop is refused after 11 requests. A redirect,
  5xx and retry sequence starts each attempt again from the requested path.
- Notes, outside acceptance:
  - `gh -- api` uses gh's own redirect rules.
  - The gitleaks bootstrap download keeps reqwest's default redirects; it sends no credential
    and checks a digest.
  - A retried GET gets a fresh count of 10 redirects per attempt.
