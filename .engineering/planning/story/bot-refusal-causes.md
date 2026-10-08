---
format: aep.planning-md/3
id: story:bot-refusal-causes
kind: story
status: active
title: Name the cause in every delivery refusal
summary: Protected-file, API 4xx, nothing-staged refusals name their cause; a succeeded API write is reported as success.
relations:
- derived_from: story:public-shared-gates
scope:
- confidence: cited
  path: src/delivery.rs
- confidence: cited
  path: src/main.rs
- confidence: cited
  path: src/policy.rs
- confidence: cited
  path: tests/delivery_refusals.rs
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-08T09:41:14Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-08T09:41:14Z", actor: "human:timo", revision: 4}
---
## Problem

Agents delivering through `b10x-gates` on 2026-10-08 could not act on its refusals, because they
did not name a cause:

- `protected file unavailable` and `protected file ownership or permissions invalid`, where the
  file existed with mode 0644 and 0600 was needed. A `git pull` in the policy repository rewrites
  the policy as 0644, so this recurs after every pull.
- `GitHub operation failed (405 Method Not Allowed); response withheld` and the same for 422. The
  API's own `message` (for example "A pull request already exists for …", "Pull Request is not
  mergeable") was withheld although it carries no private data.
- `bot Git operation refused` when nothing was staged for the commit.
- One pull request was created, then `api` reported failure because writing the local response
  file failed; the caller retried and got 422 for the duplicate.

## Contract

1. Protected-file refusals (`policy::protected_read`, `policy::protect`, `policy::private_write`)
   name the path, the observed cause and the fix:
   - missing: the path and "not found" (or the I/O error kind);
   - not a regular file / a symlink: say which;
   - mode: the observed octal mode and the needed one, e.g. `mode 0644, needs 0600 or stricter
     (chmod 600 <path>)`;
   - owner: the observed and the expected uid;
   - parent writable by group or others: the directory, its mode, and `chmod go-w <dir>`;
   - output directory writable by another user: the directory, its mode and the needed one (0700).
2. A GitHub API answer that is not 2xx is reported with its numeric status and reason phrase. For
   4xx it also carries GitHub's `message` and, for each entry of `errors`, its `resource`,
   `field`, `code` and `message`, only when:
   - the response body is JSON;
   - the text holds no match of the trusted policy's private rules (`forbidden_literals`,
     `forbidden_patterns`) and no `personal-paths` finding, checked with the same matchers
     `scan-text` uses; on a match the message is replaced by `message withheld: it matches a
     private rule` and the status is still printed;
   - control characters are removed and each message is cut to 300 bytes.
   For 5xx and any non-JSON body: status only, as today. The token, request headers and the
   request body are never printed.
3. `api --method M --path P --output O`: the output directory is checked before the request
   (exists or can be created, not writable by group or others). If the remote request succeeded
   and writing `O` still fails, the command exits 0, prints on stdout that the operation
   succeeded with the status and, where present, the response's `html_url` and `number`, and
   prints on stderr why `O` was not written. It never reports a succeeded write as failed.
4. `bot -- commit …` that Git refuses: when the index equals `HEAD`, no pathspec follows `--`
   and neither `-a`/`--all` nor `--allow-empty`/`--amend` is given, the refusal says
   `nothing staged: git add the paths, or name them after --`. Every bot Git failure names the
   verb and Git's exit status: `bot Git commit failed (exit status 1); Git's and the hooks'
   output is above`.
5. `gh -- …`: an unsupported first argument names itself and the supported list; a failing `gh`
   child names its exit status.

Nothing here changes what is admitted or refused, only what a refusal says and the exit status of
an `api` call whose remote write succeeded.

## Specification

`ess/` models the signed receipt (`gates.evidence.Receipt`) and nothing of the delivery verbs.
This change alters refusal text and the exit status of one success path; it adds no entity, field,
command or outcome to the modelled surface. The specification validates unchanged with ess 0.56.0
(`ess specify validate --path ess/`: `gates v1 — 2 file(s), valid`). The delivery verbs having no
model is a pre-existing gap, not closed here.

## Acceptance

New tests in `tests/delivery_refusals.rs`, each failing before the change. Fixtures use neutral
names (a temp directory, the user name `example`):

- `protected_read_names_mode_and_fix`: a 0644 file is refused with `0644`, `0600` and `chmod 600`.
- `protected_read_names_missing_path`: a missing file's refusal carries the path and `not found`.
- `protected_read_names_writable_parent`: a 0600 file in a 0777 directory names the directory
  and its mode.
- `private_write_names_writable_output_directory`: names the directory, its mode and 0700.
- `api_4xx_carries_github_message`: a 422 body `{"message":"Validation Failed","errors":[{"resource":"PullRequest","code":"custom","message":"A pull request already exists for example:branch."}]}`
  renders status 422 and both messages.
- `api_4xx_withholds_message_matching_private_rule`: the same with a policy literal in the
  message renders 422 and `withheld`, and not the literal.
- `api_4xx_withholds_home_path`: a message carrying a home path of `example` is withheld.
- `api_5xx_and_non_json_render_status_only`.
- `api_message_strips_control_characters_and_truncates`.
- `api_success_survives_response_write_failure`: the success path with an unwritable output
  reports success (exit 0 / `Ok`) and names the output path.
- `api_refuses_bad_output_directory_before_request`: the pre-check refuses a group-writable output
  directory without making a request.
- `bot_commit_nothing_staged_is_named`: a commit with an empty index in a temp repository is
  refused with `nothing staged`.

`cargo test --locked`, `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D
warnings` pass.

## Scope

- `src/policy.rs` (protected_read, protect, private_write): cited
- `src/delivery.rs` (Github::api, Github::gh, Github::git failure text): cited
- `src/main.rs` (the `Action::Api` and `Action::Gh` blocks only): cited
- `tests/delivery_refusals.rs` (new)
