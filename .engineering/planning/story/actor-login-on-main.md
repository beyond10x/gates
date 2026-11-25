---
format: aep.planning-md/3
id: story:actor-login-on-main
kind: story
status: draft
title: Remove the owner's login from the actor of 107 planning files on main
summary: 160 actor lines in 107 files hold a login; aep has no verb to correct an actor
revision: 1
---
## Problem

The default branch of this public repository holds the owner's login as the actor of planning
records: 160 lines of the form `actor: "human:<login>"` (transition rows) and `"actor":
"human:<login>"` (evidence files) in 107 files, counted with `git grep` on origin/main at
61c27fc:

- 72 files under `.engineering/evidence/story/`
- 5 files under `.engineering/evidence/task/`
- 28 files under `.engineering/planning/story/`
- 1 file under `.engineering/planning/task/`
- 1 file under `.engineering/planning/design/`

The rule is "the owner", never a login. `aep` wrote the actor from its own environment
(`AEP_ACTOR` unset), so every record made without that variable carries it. Pull request 59
removed the same value from its own 7 lines by recording the story again; it did not touch main.

`aep` has no verb to correct an actor. `aep plan artifact redact` replaces text in a title,
summary and body only. `set` refuses status, revision, id and kind and has no actor field.
Evidence files are written once, and the first 12 hex of the file's sha256 is part of the file
name, so an edit also renames the file. `aep plan artifact validate` refuses a committed
evidence file that differs from its committed blob.

## Goal

No file on the default branch holds the login as an actor, and `aep plan artifact validate`
exits 0 on the result.

## Constraints

- Main is not rewritten: no history rewrite, no force push. The login stays in earlier commits.
- No hand edit of an evidence file. The way to a result is a verb of `aep`, or a change to
  `aep` that adds one, decided by the owner.
- Candidate approaches, to be decided before work starts:
  - an `aep` verb that rewrites the actor of a record and renames the evidence file by its
    new digest, itself recorded as evidence (change in the `aep` repository);
  - record each affected story again as PR 59 did: the evidence is new, its `at` instants are
    new, and the original instants are lost.
- Every new `aep` write sets `AEP_ACTOR=human:operator`.

## Acceptance

- `git grep -l 'human:<login>'` on the default branch after the change prints nothing.
- `aep plan artifact validate` exits 0.
- A test or a gate step fails when an added line holds an actor that is a login.
