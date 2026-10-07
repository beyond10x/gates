---
format: aep.planning-md/3
id: story:hex-path-components
kind: story
status: implemented
title: Refuse home paths written as hex-encoded path components
summary: personal-paths decodes JSON components arrays of hex strings and refuses a decoded home path.
relations:
- derived_from: story:public-shared-gates
scope:
- confidence: cited
  path: src/scan.rs
- confidence: cited
  path: tests/adversary_hex_paths.rs
- confidence: cited
  path: tests/security.rs
revision: 9
transitions:
- {from: "draft", to: "proposed", at: "2026-10-07T06:19:53Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-07T06:19:53Z", actor: "human:timo", revision: 3}
- {from: "active", to: "implemented", at: "2026-10-07T08:12:36Z", actor: "human:timo", revision: 9, decided_on: {"recorded":{"test_result":1,"review_outcome":2,"verification":1}}}
---
## Problem

ESS writes `<out>/.ess-output/state.json` with the absolute output directory as an array of
hex-encoded path components: `payload.root` is `{"components": [...], "encoding": "UnixBytes1"}`,
each component the hex of one path segment with the leading `/` stripped. In two public
repositories such records reached `main` and decoded to a home directory followed by a user name.
`personal-paths` and `common / Security and privacy` admitted every one of them, because the rule
matches only path text and `686f6d65` is not the text `home`.

## Contract

- Every JSON array under a `"components"` key whose elements are all hex strings is decoded,
  component by component, and joined as `/` + components separated by `/`. The `UnixBytes1`
  marker is not required: a renamed or reordered marker must not reopen the gap, and an array
  that decodes to `home/<name>` names a home directory whatever it is labelled.
- The decoded path is held to the same `personal-paths` matcher as plain text: `/home/<name>/`,
  `/Users/<name>/` and a bare `/home/<name>` are refused; a relative array such as
  `["src","home","x"]` is not, as `src/home/x` is not.
- A component that does not decode as hex (odd length) contributes its own text.
- Compact (single-line) and pretty-printed (multi-line) JSON are both read. The finding is
  reported on the line where the `"components"` key starts; its content digest binds every line
  the array spans, so a historical exception cannot admit different components.
- Inheritance is unchanged in meaning: a decoded finding is inherited only when every line the
  array spans is already present in that path's previous version. A regenerated single-line
  `state.json` is therefore a new line and is refused.
- The delivery verbs (`gh --`, `api --input`, `scan-text`) refuse the same decoded paths.
- Binary units (NUL in the first 8 KiB) stay out of the privacy rules.
- No rule is added to the roster, no policy field changes and the receipt format is unchanged;
  the version increment invalidates retained receipts.

## Specification

`ess/` models the signed receipt (`gates.evidence.Receipt`). This change adds no entity, field,
command or outcome: `personal-paths` stays one rule in the closed roster and its findings keep the
receipt's shape. The specification is validated unchanged with the newest `ess`.

## Acceptance

Tests in `tests/security.rs`, each failing before the change. Fixtures use the neutral name the
file already uses (`fixture-person`) and are built at run time, both the plain path and its hex
components, so the test source carries neither a home path nor an encoded one:

- `hex_path_components_compact_home_is_refused`: a one-line `state.json` whose root decodes to
  the Linux home of `fixture-person` is refused with `personal-paths` on line 1.
- `hex_path_components_pretty_home_is_refused`: the same root, pretty-printed, is refused on the
  line of the `"components"` key.
- `hex_path_components_macos_home_is_refused`: a root decoding to the macOS home of
  `fixture-person`.
- `hex_path_components_relative_paths_are_admitted`: ledger arrays such as `["docs"]` and
  `["src","home","x"]` raise nothing.
- `hex_path_components_regenerated_line_is_refused`: a single-line file whose previous version
  carried the same root but a different line is refused; an unchanged line is inherited.
- `scan_text_refuses_hex_path_components`: `scan-text` refuses a file carrying the array.

`cargo test --locked`, `cargo fmt --all --check` and
`cargo clippy --all-targets --locked -- -D warnings` pass. Removing the decoding makes the
refusal tests fail (mutation evidence).

## Scope

- `src/scan.rs`: `Matchers` (decoder, `hex_paths`, `personal`, `text`, `wrapped_lines`), `run`
  (decoded pass, set-based line lookups), `finding` (returns whether it recorded). Cited from
  commits `7e2dccb` and `a9413a7`.
- `tests/security.rs`: the acceptance tests. Cited.
- `tests/adversary_hex_paths.rs`: added by the adversary, pass 1. Cited. Not in the original
  scope.
- `README.md`, `CHANGELOG.md`, `Cargo.toml`, `Cargo.lock`: the coordinator's closing commit.
