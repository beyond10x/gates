---
format: aep.planning-md/3
id: story:published-merge-server-errors
kind: story
status: implemented
title: Prove historical merges when GitHub answers 5xx for their pull-request list
summary: Retry GETs on 5xx, name the failing read, and fall back to the pull request the merge subject names
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-10-22T15:49:20Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-22T15:49:20Z", actor: "human:timo", revision: 4}
- {from: "active", to: "implemented", at: "2026-10-22T16:05:55Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"test_result":1,"review_outcome":1}}}
---
## Problem

The pre-push hook and publication prove each historical GitHub merge in delivery ancestry with
`GET /repos/<owner>/<repo>/commits/<merge>/pulls`. On 2026-10-22 that read answered 500 for 10 of
the 23 merges in `beyond10x/harness` since its baseline `709a2eb`
(`~/.cache/harness-wave/probe-merges.sh`, run with b10x-gates 0.1.21). The same 500 came back to
a personal token with the same query string; one URL answered 500 four times in a row and then
200, and which query string fails changes from request to request. Any 5xx aborted the push, with
no retry and no path in the error. `loom` saw the same.

## Contract

- A GET answered with a 5xx is sent again, at most 5 attempts in all, with 0.5/1/2/4 s waits.
  Other statuses and transport errors return at once. Writes are never retried.
- Every published-merge read that fails names `GET <path>` in its error.
- When the association list still answers 5xx, the merge's subject (`Merge pull request #<n> from
  …` or `… (#<n>)`) supplies a pull request number. The subject is a lookup key, not evidence: the
  authenticated `/pulls/<n>` record must carry `number == n` and `merge_commit_sha == <merge>`,
  and then passes every check a listed record passes (merged, closed, merged by the exact bot,
  same repository, default-branch base, head is the second parent, private-repository accounts,
  clean local merge tree, squash rules).
- Fail closed: a subject naming no pull request (branch updates), a 4xx on the list, a record
  naming another commit or another number, and a failing `/pulls/<n>` all refuse.
- The fallback cannot show that no second pull request names the same merge, which the list
  shows. That does not change what the merge's tree is proved against.

## Acceptance

`tests/published_merge.rs`: `a_failing_association_list_is_replaced_by_the_pull_request_the_merge_names`,
`a_failing_association_list_without_a_named_pull_request_refuses_and_names_the_read`,
`a_client_error_on_the_association_list_never_falls_back`,
`the_named_pull_request_must_name_this_commit_as_its_merge`,
`a_subject_naming_another_pull_request_refuses`,
`the_named_pull_request_is_proved_as_strictly_as_a_listed_one`,
`a_named_merge_must_still_be_the_clean_local_merge_of_its_parents`,
`the_named_pull_request_s_own_read_failing_refuses_and_names_both_reads`,
`a_private_named_merge_still_needs_the_exact_bot_accounts`,
`a_named_squash_merge_is_admitted_only_where_a_listed_one_is`,
`an_update_branch_s_final_merge_falls_back_to_the_pull_request_it_names`,
`an_update_branch_s_final_merge_naming_another_pull_request_refuses`,
`a_failing_association_list_of_a_branch_update_refuses`; unit tests in `src/delivery.rs`
(retry) and `src/published_merge.rs` (subject parsing).
