---
format: aep.planning-md/3
id: review-result:published-merge-server-errors-security-review
kind: review-result
status: active
title: 'Security review: published-merge 5xx retry and named pull request fallback'
relations:
- reviews: story:published-merge-server-errors
revision: 1
---
## Verdict

Holds after one fix. The reviewer found one admit-on-error path in the fallback, which was
fixed before merge. Two warnings are deferred to `story:published-merge-review-followups`.

```
unit: b10x-gates published-merge 5xx retry and named pull request fallback, fix/published-merge-5xx
verdict: INFEASIBLE (1 red case, fixed) + 1 NEEDS-CHANGE warning (deferred)
cases: executed 145→147, red 1 → 0
origin: introduced 3 / pre-existing 0 / undecided 0
```

## Cases added

- `review_a_server_error_on_a_later_page_keeps_the_ambiguity_page_one_showed`: a full page 1
  showing two pull requests naming the merge, then page 2 answering 500. The candidate fell
  back and admitted the merge. Fixed: only a failure of page 1 falls back (`later_pages` in
  `src/published_merge.rs`), and a later page failing refuses with its `GET` path.
- `review_a_signed_merge_s_subject_is_read_after_its_signature_only`: a `#` inside a `gpgsig`
  header is never read as the subject. Green.

## Findings

| # | Where | Verdict | Disposition |
|---|---|---|---|
| F1 | `src/published_merge.rs` `pull_associations` | INFEASIBLE, integrity | fixed in this unit |
| F2 | `src/delivery.rs` `api_response` GET-only retry | NEEDS-CHANGE, untested guard | deferred |
| F3 | `src/published_merge.rs` `read` | CONFIRMED, note: status text printed twice | deferred |

## Reviewed and cleared

Subject parsing is only a lookup key: admission needs `/pulls/<n>.merge_commit_sha == <merge>`.
The fallback always takes the terminal-merge path. Two-parent trees are rebuilt from local
parents, and squash merges stay public-only. On the update-branch paths the merge record is
checked before the list is read, and private repositories run the bot-account checks on the
same record. Only a 5xx is re-sent, and no caller maps a 5xx to "absent". Error text holds only
the repository, oids, a number, the default branch and the status.
