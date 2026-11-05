---
format: aep.planning-md/3
id: story:api-writes-no-redirect
kind: story
status: draft
title: Send a GitHub write once, to an admitted path, never along a redirect
tags:
- from-finding
relations:
- informed_by: review-result:review-followups-adversary-1
revision: 3
---
## Problem

Found by `review-result:review-followups-adversary-1` (pre-existing, outside that unit's
acceptance). The GitHub HTTP client keeps reqwest's default redirect policy (up to 10,
`src/delivery.rs` around the client builder). A 307 or 308 answer makes reqwest send a POST,
PUT, PATCH or DELETE again, body included, to the `Location`, below the retry decision and
past the API path admission check. reqwest drops the authorization header on a redirect to
another host; a same-host redirect keeps it.

## Proposal

Refuse redirects for write methods (or for every request, if GitHub's renamed-repository 301
for reads is handled explicitly), so a write is sent once, to an admitted path only.

## Acceptance

A local test server answering 307 to a write shows the write sent once and refused naming the
redirect; a GET that GitHub answers with a redirect still behaves as decided in the story.
