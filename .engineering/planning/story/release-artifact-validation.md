---
format: aep.planning-md/3
id: story:release-artifact-validation
kind: story
status: active
title: Validate executable release artifacts with binary-aware privacy and secret checks
relations:
- derived_from: story:public-shared-gates
scope:
- confidence: inferred
  path: CHANGELOG.md
- confidence: inferred
  path: Cargo.lock
- confidence: inferred
  path: Cargo.toml
- confidence: inferred
  path: README.md
- confidence: inferred
  path: src/artifact.rs
- confidence: inferred
  path: src/lib.rs
- confidence: inferred
  path: src/main.rs
- confidence: inferred
  path: tests/artifact.rs
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-10-03T08:17:09Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-03T08:17:09Z", actor: "human:timo", revision: 4}
---
## Problem and authorization

The operator rejected a one-artifact scan exception and requested a proper fix followed by the ESS release. Applying scan-text to executable instruction bytes produced a three-byte private-identifier match in .text. The text check must remain strict. Gates must offer a supported executable artifact validation path that verifies the artifact and scans its embedded text/provenance and secrets rather than silently skipping binaries or treating machine instructions as prose.

## Acceptance

A bounded Rust/clap command validates the supported executable format and rejects malformed, truncated or unsupported inputs. A synthetic ELF with forbidden bytes only in executable instructions passes the privacy portion; the same forbidden identifier in embedded data/text refuses, as do embedded personal paths and real secret fixtures. Secret scanning must execute over meaningful extracted data, with missing scanner or scanner errors refusing; a zero-byte skipped binary scan is never success evidence. Preserve every existing scan-text and Git admission safeguard. Bind the report to the complete original artifact SHA256 and document precisely what is scanned and what is not. No policy exceptions, changed baselines, credential exposure, candidate execution or custom cryptography.

Independent additive regression review and full repository correctness/format/strict-Clippy gate are required. Validate the actual static Gates release artifact through the delivered check before publication/adoption. This is a release-tooling dependency, not an ESS language or transport change.
