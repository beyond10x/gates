---
format: aep.planning-md/3
id: review-result:ci-fetch-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: ci fetches the head by id'
relations:
- reviews: story:ci-fetch-head-by-sha
revision: 1
---
verdict: INFEASIBLE, 2 findings
cases: executed 24→34, red 2
origin: introduced 1, pre-existing 0, undecided 1

Unit diff c7343c2..ce90661, attacked at e72cf1c. Cases in `tests/adversary_ci_fetch.rs`.

- Warning: when the id fetch was refused and the fallback ref lacked the head, the id's
  refusal was discarded and `ci` failed with a misleading rev-parse hint
  (`a_fallback_ref_without_the_head_names_the_refused_id`).
- Note: the credential check stripped control characters but not Unicode format characters,
  so a token split by U+200B was printed (`a_token_split_by_a_format_character_is_withheld`).
- Both fixed in 09f788c; both cases green and committed.
- Held (8 regression cases): the fallback binds the candidate to the head id; a fork pull
  request is fetched from the base repository; option-like, short, uppercase, range and
  ref-name heads are refused before any fetch; a push never falls back to a pull ref; private
  terms and personal paths in git's message are withheld.
