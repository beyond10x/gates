---
format: aep.planning-md/3
id: story:consumer-pins-trusted
kind: story
status: draft
title: Every qualifying consumer calls a trusted Gates workflow in canonical shape
summary: Move the 43 qualifying consumers' shared-gates.yml to the trusted Gates commit in canonical caller shape and record the first qualifying run
relations:
- depends_on: story:ci-committer-pr-bound
revision: 1
---
# Story: Every qualifying consumer calls a trusted Gates workflow in canonical shape

## Outcome

Each repository whose default branch carries the bot rulesets and the required common check calls
`beyond10x/gates/.github/workflows/common.yml` at a Gates commit on the trusted list, in the
canonical caller shape. Its default-branch check can therefore prove `B`, and its pushes stop
re-judging proved history.

Story 4 of `design:push-range` (revision 2), finding G5.

## Context

On 2026-11-24, 43 public repositories had both rulesets. Their callers download Gates binaries:

| binary | repositories |
|---|---|
| 0.1.3 | 17 |
| 0.1.4 | 1 |
| 0.1.5 | 2 |
| 0.1.7 | 3 |
| 0.1.8 | 7 |
| 0.1.21 | 6 |
| 0.1.24 | 1 (gates itself) |
| 0.1.26 | 6 |

So 37 of them run binaries from 0.1.3 to 0.1.24. None of these binaries checks committers.

## Acceptance

- **The pin moves.** For each of the 43 repositories, a bot pull request moves
  `.github/workflows/shared-gates.yml` to the newest trusted Gates commit. The file keeps the
  canonical shape:
  - one job `common`, with the trusted `uses:` ref;
  - a `secrets:` map whose only keys are `B10X_GATES_POLICY_GZ` and/or `B10X_GATES_POLICY`, each
    mapped by the same name;
  - no `with:`, `if:` or `name:`.
- **The pull request merges** under the repository's own process.
- **Evidence it qualifies.** After the merge, the repository's next default-branch push run shows
  `referenced_workflows` at the trusted id, and `b10x-gates` stops printing `bound=baseline` for it.
  Both are recorded per repository.
- **Not yet qualified.** A repository whose run is red after the move (a history finding the new
  binary reports) is listed with its finding coordinates. Its exceptions are prepared for the owner,
  and its baseline is not moved.
- **Tracking.** A table in the story's evidence lists all 43: old pin, new pin, the pull request,
  and the first qualifying run.

## Out of Scope

- Rulesets (the owner's).
- The 20 repositories with the authority ruleset but no required common check, the 6 without the
  authority ruleset, and private repositories. They keep the baseline range (Q1 = A).
