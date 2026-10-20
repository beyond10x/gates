---
format: aep.planning-md/3
id: story:ess-inner-workings
kind: story
status: draft
title: Model the bot verbs and their refusals in ESS and hold the model in the gate
summary: Declare every bot, gh and api verb and its refusals as ESS commands, pin the ess release, and make b10x-gates gate and CI fail on an invalid specification or a failed conformance scenario.
relations:
- informed_by: story:api-protection-writes
scope:
- confidence: inferred
  path: .github/workflows/quality.yml
- confidence: inferred
  path: README.md
- confidence: inferred
  path: ess/domains/delivery.yaml
- confidence: inferred
  path: ess/domains/evidence.yaml
- confidence: inferred
  path: ess/ess-inputs.yaml
- confidence: inferred
  path: ess/system.yaml
- confidence: inferred
  path: src/main.rs
revision: 2
---
## Problem

`ess/` holds a specification nothing checks. Read on 2026-10-20 at `f504f16`:

- `ess/system.yaml` (`format: ess/24`) and two domains, `ess/domains/delivery.yaml` and
  `ess/domains/evidence.yaml`; no `ess-inputs.yaml`, so no `ess` release is pinned.
- No workflow under `.github/workflows/` and no step of `b10x-gates gate` (`src/main.rs`,
  `Action::Gate`: `cargo test`, `cargo fmt --check`, `cargo clippy`) runs `ess`. A refusal the
  code drops, or a refusal the code adds without a declaration, stays green.
- The delivery domain declares 8 commands: `Merge`, `Revert`, `DeleteBranch`, `InstallHooks`,
  `ValidateArtifact`, `LoadCiPolicy`, `PublishPolicy`, `BotApi`. The other bot verbs (`commit`,
  `tag`, `push`, `fetch`, the `gh` verbs) and their argument refusals (`src/bot_args.rs`) are not
  declared.
- `ess verify conform synthesize --path ess` with ess 0.60.0: `49 scenario(s) (0 authored),
  19 refusal(s)`. One refusal names an entity no outcome `creates:`.

Asked by the operator on 2026-10-20 through the monitoring session: model gates' inner workings
with the `ess:specifying` skill, and hold the model in the gate.

## Proposal

- Add `ess/ess-inputs.yaml` (`format: ess-inputs/2`, `requires:` the ess release the gate runs)
  and move the specification to the newest format that release implements.
- Declare every `bot` verb (`commit`, `tag`, `push`, `fetch`, `merge`, `revert`, `delete-branch`),
  `gh` and `api` as commands, each argument refusal as an outcome with a named error, including
  `BotApi`'s protection-write refusal. The source for each outcome is the code's refusal text and
  its test; a refusal with no test is an `UNMAPPED:` marker, not a guess.
- Close the 19 synthesis refusals or name each one that needs a construct ESS lacks.
- Add `ess specify validate` and a conformance step to `b10x-gates gate` and to CI: synthesize the
  suite and run it against the built binary through a target adapter (`ess:testing-conformance`).

## Acceptance

- `ess specify validate --path ess` exits 0 under the pinned release, with no `implied_relation`
  warning and no `UNMAPPED:` marker left without a named owner question.
- `ess verify conform synthesize --path ess` reports 0 refusals, or each remaining one is named
  in this story with its code.
- `b10x-gates gate` and the CI `correctness` job fail when the specification does not validate
  and when a conformance scenario fails; both shown red once (a declaration broken on purpose).
- Removing one declared refusal from `src/bot_args.rs` turns a conformance scenario red
  (mutation recorded).

## Non-goals

- Changing any refusal's behaviour; this story models what the code does today.
- Publishing generated projections (schema, OpenAPI, docs).
