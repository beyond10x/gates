---
format: aep.planning-md/3
id: story:gh-published-file-spellings-scanned
kind: story
status: draft
title: Every spelling of a file gh publishes has its content scanned
relations:
- derived_from: story:public-shared-gates
revision: 1
---
## Problem

`b10x-gates gh` reads and scans the content of a file `gh` publishes only when the option is
written as two words, `--notes-file <f>` or `--body-file <f>` (`src/main.rs`, `FILE_OPTIONS`).
These spellings reach `gh` with the file's content unscanned, the path being only a relative
name that breaks no rule:

- `release create v1 -F notes.md`
- `release create v1 --notes-file=notes.md`
- `pr create ... -F notes.md` and `--body-file=notes.md`
- `release new v1 notes.md` (`new` is an alias of `create`, gh `create.go:158`)
- `release -R <owner>/<repo> create v1 notes.md`

Found by the security review of the admission of release asset paths on 2026-11-27; identical
at main 9f58450. A patch with red tests is kept by the coordinator.

## Outcome

Every spelling `gh` reads as a file it publishes (short option, `--opt=value`, aliases, `-R`
before the verb) has the file's content scanned as the two-word spelling has.

## Acceptance

Each spelling above, with a relative file holding a private literal, is refused before a token
is minted.
