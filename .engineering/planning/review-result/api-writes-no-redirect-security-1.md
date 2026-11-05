---
format: aep.planning-md/3
id: review-result:api-writes-no-redirect-security-1
kind: review-result
status: active
title: 'Security review 1: API writes are never sent along a redirect'
relations:
- reviews: story:api-writes-no-redirect
revision: 1
---
verdict: nothing that holds the unit, 3 INFEASIBLE notes
cases: executed 14→16, red 0
origin: introduced 0, pre-existing 0, undecided 0

Unit diff 57527c1..493ea00. Cases in `tests/security_api_writes_no_redirect.rs`, 5bc1146.

- Held, with each case red under a mutation of its guard:
  - Every method but exact `GET` and `HEAD` (`get`, `Head`, PROPFIND, QUERY, LINK, TRACE) is a
    write that a redirect never repeats.
  - A fixed-seed property over 600 generated `Location` values: another host is never sent
    anything, and a read follows only the `Location` exactly as written to an admitted path.
- Note, INFEASIBLE: no test runs the production constructor `from_token`, because tests use
  `for_loopback_test`. Both constructors share `client()`, which sets `Policy::none()`. A
  test of `from_token` would need a TLS stand-in for the API host.
- Note, INFEASIBLE: `b10x-gates gh -- api` writes through gh's own HTTP client and its
  redirect rules. The README promises the rule only for the API client.
- Note, INFEASIBLE: `api_path_admitted` lets a percent-encoded dot segment
  (`/a/%2e%2e/b`) through on the first request, and the URL parser sends it as `/b` on the
  same host. No caller reaches it: internal callers encode `%` as `%25`, and the `api`
  protection check decodes the path first.
