---
format: aep.planning-md/3
id: review-result:refusal-causes-security-1
kind: review-result
status: active
title: 'Security review 1: delivery refusal causes and routes'
relations:
- reviews: story:bot-refusal-causes
- reviews: story:bot-supported-routes
revision: 1
---
needs-revision

Security review of `git diff 2671c7d 3bf4987` (both units), by the security-reviewer role, in tree
`gates-review-causes`. 10 cases added in `tests/review_refusal_causes.rs`: 6 red, 4 green.
Full suite with the pinned scanner: every file green except those 6.

| # | file:line | verdict | origin | measured |
|---|---|---|---|---|
| 1 | `src/bot_args.rs:77` | NEEDS-CHANGE | introduced | the prefix length limit admits `--m`; `git push --m origin` deleted a branch in a scratch repository |
| 2 | `src/delivery.rs:229` | NEEDS-CHANGE | introduced | a path given without `--` whose commit a hook refused is reported as nothing staged |
| 3 | `src/delivery.rs:230` | NEEDS-CHANGE | introduced | a merge in progress whose tree equals HEAD, refused by a hook, is reported as nothing staged |
| 4 | `src/bot_args.rs:40` | CONFIRMED | pre-existing | `commit -nm x` skips the pre-commit hook |
| 5 | `src/bot_args.rs:39` | CONFIRMED | pre-existing | `--no-verif` is accepted by Git and skips hooks |
| 6 | `src/bot_args.rs:43` | CONFIRMED | pre-existing | `--receive-pack=`/`--upload-pack=` run a caller-chosen command with the bot token in its environment |
| 7 | `src/bot_args.rs:62` | INFEASIBLE | introduced | repository config `remote.<name>.mirror` deletes through a plain push; an argument check cannot see it |
| 8 | `src/delivery.rs:197` | INFEASIBLE | pre-existing | a 2xx non-JSON body is reported as failure after the remote write succeeded |

Checked without fault: token and request body never printed; 4xx message vetting against split,
hidden, escaped, truncated and nested forms; `html_url` vetting; output directory checked before
the request; argument check before credential minting; protected-file refusals refuse every case
`2671c7d` refused (by reading).

```findings
- file: src/bot_args.rs
  line: 77
  category: boundary
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'the length limit of 2 on push option prefixes admits `--m`, which Git accepts as `--mirror` and which deleted a remote branch'
- file: src/delivery.rs
  line: 229
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'a commit with a path given without `--` that a hook refused is reported as nothing staged'
- file: src/delivery.rs
  line: 230
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: 'a merge whose tree equals HEAD, on the route the check prints, is reported as nothing staged when a hook refuses it'
- file: src/bot_args.rs
  line: 40
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the `-n` guard only matches `-n` on its own, so `commit -nm` skips the pre-commit hook'
- file: src/bot_args.rs
  line: 39
  category: boundary
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: 'the abbreviation `--no-verif` is accepted by Git and skips hooks on commit and push'
- file: src/bot_args.rs
  line: 43
  category: integrity
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: '`--receive-pack=` and `--upload-pack=` run a command the caller chooses, with `B10X_BOT_TOKEN` in its environment, as `--exec` does'
- file: src/bot_args.rs
  line: 62
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: 'repository config with `remote.<name>.mirror` or a deleting push refspec deletes branches through a plain `push origin`, which an argument check cannot see'
- file: src/delivery.rs
  line: 197
  category: judgement
  severity: note
  verdict: INFEASIBLE
  origin: pre-existing
  message: 'a 2xx answer that is not JSON is reported as a failure after the remote write succeeded'
```
