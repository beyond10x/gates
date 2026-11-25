---
format: aep.planning-md/3
id: story:exception-digest-path-pattern
kind: story
status: draft
title: One trusted exception for a byte-identical file in any version folder
summary: An exception can bind a content digest to a path pattern with a free version segment, so a copy per bundle version needs no new exception
revision: 3
---
## Problem

A contract bundle repository copies the same 16 test-vector files into a new version folder for
every bundle version. Each copy is flagged by a secrets rule, and each needs its own trusted
exception: repository, rule, `location` (the exact path, which holds the version), `content_sha256`
and `line`. Today 208 of the policy's 467 exceptions are these 16 files, once for each of 13
versions, and every new bundle version adds 16 more, each of which needs the owner's decision.

The policy's exception form cannot name "the same file in any version folder":

- `Exception::covers` (`src/policy.rs:42-49`) matches `location` exactly, or as a prefix when it
  ends in `*`. A `*` anywhere else is part of an exact name, so a path with a free version segment
  in the middle cannot be written.
- The prefix form with a digest (`content_sha256` of 64 hex) admits every line under the prefix
  with that digest, but the prefix cannot end at a version folder and still name one file.
- For the secrets rule, `content_sha256` is the digest of the whole file (`src/scan.rs`,
  `finding()` is called with the unit's bytes), and `line` is the line the scanner reports. So
  each file needs one exception per reported line and per version. For the privacy rules the
  digest is of the exact flagged line. `line` is exact (or 0 for any line).

## Goal

One exception can admit a byte-identical copy of a file under any version folder, and nothing
else: a path pattern with the version segment free, bound to the content digest.

## Constraints

- The exception stays a trusted policy entry bound to an exact rule, repository and content
  digest (`AGENTS.md`). The pattern widens the location only; it never widens the content.
- A pattern admits no path that a human could not have meant: no pattern that is only `*`, and a
  pattern with a free segment still names the fixed segments around it.
- No policy file is read or changed by this story. The consumer's own policy entries are
  rewritten only after the owner accepts the form.
- Existing exact-path and trailing-`*` entries keep their meaning.
- The story names the consumer by a description only.

## Design decision

Taken by the host operator on the owner's word of 2026-11-25 04:03 CET ("take decissions for
me"), as D117: the free segment is a glob with `*` for one path segment inside `location` (for
example `contracts/*/vectors/<file>`), with no new field. The loader refuses a bare `*` and a
pattern with an empty fixed part.

Check made by the owner's operator on the owner's policy at 04:06 CET, as given to this story
(not read by the story's author):

- 0 `location` values hold a `*` before the end, so no existing exact name changes meaning.
- 8 `location` values end with `*` (the trailing-prefix form), which must keep its meaning.

The story stays a draft. No code before the owner is back.

## Compatibility

- The chosen form: a glob inside `location` adds no field. An older binary parses the policy, reads the pattern as
  an exact name, and does not match the copies: it refuses them, which is a fail-closed result,
  and it does not refuse the policy. This is not a parse-breaking change, but an older caller
  fails the gate on those copies until it moves.
- Not chosen: a new field in `Exception` is breaking: the wire model is `deny_unknown_fields`
  (`src/policy.rs:26`), and an older binary refuses the whole policy with "policy format
  invalid" (README, "A version 2 policy is unreadable by an earlier binary"). The release must
  then reach every caller before the organization secret changes.

## Acceptance

- A byte-identical copy (same file digest) under a path that matches the pattern passes.
- The same digest under a path that does not match the pattern is refused.
- A changed byte under a matching path is refused.
- Existing exact-path entries and trailing-`*` entries keep working: their tests do not change.
- A pattern that is only `*`, or has an empty fixed part, is refused when the policy is loaded.
- A trailing-`*` location keeps matching as a prefix; a `*` before the end matches exactly one
  path segment.
- The story's change names that the policy schema is unchanged and the form is not breaking, per
  the section above.
