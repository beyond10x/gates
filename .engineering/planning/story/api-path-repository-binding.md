---
format: aep.planning-md/3
id: story:api-path-repository-binding
kind: story
status: draft
title: Bind the path of an api write to the repository it names
summary: api sends to any absolute path with the bot token; --repository is not checked against the path
revision: 1
---
## Problem

`b10x-gates api --method <m> --path <path> --input <file> --repository <owner/name>` sends the
request to `<path>` with the bot's token. `--repository` is not bound to `<path>`: the only
guard on the path is that it is absolute and holds no `..` and no `#`
(`api_path_admitted`, `src/delivery.rs:579`; the `Action::Api` branch of `src/main.rs`). A caller
can write to any repository the bot's token reaches, including one outside the policy's
repository list.

Observed 2026-11-25 01:38 to 01:39 CET in another session (reported by the host operator):
`b10x-gates --repository <repo A> --policy <policy> gh -- issue create -R <outside repo> ...`
was refused ("unsupported GitHub delivery command `issue`; supported: release, pr, run,
workflow, api, repo"). Right after it, `b10x-gates api --method POST --path
/repos/<outside repo>/issues --input <json> --repository <repo A>` answered 201 and opened an
issue in that outside repository as the bot. The post was the owner's pick, so nothing went
wrong; the gap is that the gate allowed it without asking.

Correction to the report, verified in source: the body of an `api` write is scanned. The
`Action::Api` branch of `src/main.rs` calls `refuse(&matchers(policy), input, raw)` on the
`--input` file before the request, so a private rule in the body is refused. What the gate does
not read is the response, which is written to `--output` and reported, and the `--path` itself
(a private literal in a path is sent, not scanned).

## Goal

A write by `api` reaches only the repository named in `--repository`, or an exact repository
the policy lists for this purpose, and the refusal names the path and the repository.

## Constraints

- Whether `api` is meant to write outside the named repository is the owner's decision. This
  story records the gap; the fix and any policy change are ordered by the owner.
- Reads (GET) may stay unbound; the decision is part of the story.
- No policy file change from this story.

## Acceptance

- A test sends `api --method POST --path /repos/<other>/<repo>/issues` with a different
  `--repository` and the command refuses before a token is minted.
- A test with `--path` inside the named repository passes the same guard.
- The test fails when the binding check is removed.
