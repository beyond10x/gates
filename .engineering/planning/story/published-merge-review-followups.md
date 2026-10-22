---
format: aep.planning-md/3
id: story:published-merge-review-followups
kind: story
status: draft
title: Test the GET-only retry guard and print a refused read status once
summary: Deferred F2 and F3 from the 0.1.23 security review.
relations:
- derived_from: story:published-merge-server-errors
revision: 1
---
## Problem

The 0.1.23 security review (`review-result:published-merge-server-errors-security-review`) left
two findings for after the release:

- F2: the condition that keeps writes from being retried after a 5xx (`method == Method::GET`
  in `Github::api_response`, `src/delivery.rs`) has no test. `Github::send` is hard-wired to
  api.github.com, so no test reaches it.
- F3: `read` in `src/published_merge.rs` puts the inner error's text into its own context, so
  full error output prints the status twice.

## Contract

- The retry decision for a method is a pure function, or the sender is injected. A test covers
  POST, PUT, PATCH and DELETE being sent once after a 5xx, and fails if the GET-only guard is
  removed.
- A refused published-merge read prints the `GET <path>` and the status once each.

## Acceptance

A test in `src/delivery.rs` fails with the guard removed (mutation recorded). A test in
`tests/published_merge.rs` asserts the status text appears once in a refusal.
