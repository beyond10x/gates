---
format: aep.planning-md/3
id: story:gh-release-download-dir-admitted
kind: story
status: draft
title: gh release download admits a local --dir as run download does
relations:
- derived_from: story:public-shared-gates
revision: 1
---
## Problem

The release process verifies a release by downloading its assets. `b10x-gates gh -- release
download <tag> -R <owner>/<repo> --dir <a directory under the home directory>` is refused with
"argument 7 breaks 1 private rule(s): line 1 personal-paths" (0.1.32, 2026-11-27). The value of
`--dir` of `release download` is a local directory `gh` writes to and sends nowhere, as it is
for `run download`, which 0.1.31 admits. The releases 0.1.31 and 0.1.32 were verified against
GitHub's own asset digests instead of downloaded bytes.

## Outcome

`release download` admits the value of `--dir`/`-D` (and `--dir=`) as `run download` does, with
the same skipping of option values and the same end at `--`; every other rule still applies, and
every other argument is scanned as before.

## Acceptance

`release download <tag> -R <repo> --dir <home path>` passes; a private value of another option
(`--pattern`, `--output`) is still refused; `run download` unchanged.
