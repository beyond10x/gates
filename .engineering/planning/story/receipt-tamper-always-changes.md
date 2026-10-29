---
format: aep.planning-md/3
id: story:receipt-tamper-always-changes
kind: story
status: implemented
title: Make the receipt signature tamper test always change the signature
revision: 5
transitions:
- {from: "draft", to: "proposed", at: "2026-10-29T10:06:55Z", actor: "human:timo", revision: 3}
- {from: "proposed", to: "active", at: "2026-10-29T10:06:56Z", actor: "human:timo", revision: 4}
- {from: "active", to: "implemented", at: "2026-10-29T10:06:56Z", actor: "human:timo", revision: 5, decided_on: {"recorded":{"test_result":1}}}
---
## Problem

`receipt_rejects_tampering_wrong_repository_signer_policy_and_incomplete_results`
(`tests/security.rs`) tampered with a receipt signature by overwriting its first two hex
characters with `00`. The fixture key is random, so about one signature in 256 already starts
with `00`; the tamper then changes nothing, the receipt still verifies, and the assertion
fails. The `main` push run 40853255914 of `c949e63` failed this way on 2026-10-29 and passed
on re-run, while the pull-request run of the same commit passed.

## Proposal

- The tamper flips the lowest bit of the first decoded signature byte, so it always changes
  the signature, and asserts that the tampered value differs from the original.
- A seeded test finds the first deterministic key whose signature starts with byte `0x00`
  and shows that the former tamper leaves it unchanged while the bit flip does not.

## Acceptance

- `tests/security.rs`: `receipt_rejects_tampering_wrong_repository_signer_policy_and_incomplete_results`
  uses the bit flip; `a_fixed_byte_tamper_can_leave_a_signature_unchanged_and_a_bit_flip_cannot`
  passes. Test-only; it rides the next release under Unreleased.
