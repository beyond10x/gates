---
format: aep.planning-md/3
id: review-result:review-followups-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: GET-only retry and refused read status'
relations:
- reviews: story:published-merge-review-followups
revision: 1
---
verdict: CONFIRMED, 2 notes; the write-retry guard held
cases: executed 141→148, red 2
origin: introduced 1, pre-existing 0, undecided 1

Unit diff 96d0ba0..4bde5ec, attacked at 09f788c. Cases in
`tests/adversary_review_followups.rs`.

- Note: the read's own error type hid a refused read's 5xx from the public `is_server_error`
  and from `downcast_ref::<ApiFailure>()`. Fixed in 7314713 and 24a68d8: a refused read is the
  `ApiFailure` itself, naming its read, and `is_server_error` walks the whole chain.
- Note: the fallback's combined refusal dropped the named read's deeper causes. Fixed in
  7314713.
- Held: all six write methods are sent once after a 5xx; a transport error, timeout or 429 is
  never retried; GET keeps 5 attempts with doubling backoff; a refused read prints its path
  and status once and withholds response bodies.
- Pre-existing, outside the acceptance: the HTTP client follows 307/308 redirects for writes
  below the retry decision and past the API path check.
- Mutant not reachable by a test: passing `&Method::GET` at the call site.
