unit: story:published-merge-delivery, 270c290 plus stable implementation and coordinator version 0.1.6
verdict: CONFIRMED — one blocker at proof-list admission
cases: executed 102→108, red 1; 7 existing ignored cases unchanged
origin: introduced 0 / pre-existing 0 / undecided 1
wrote-outside-worktree: assigned scratch files and existing assigned compiler target; full private manifest retained
needs-coordinator: reject malformed list entries before uniqueness filtering while preserving explicit nullable PR discriminators

```text
git --no-pager diff --stat
 .engineering/planning/journal.jsonl                |  1 +
 .../planning/story/published-merge-delivery.md     | 12 ++++++---
 .engineering/waves/published-merge-delivery.md     | 14 ++++++++--
 CHANGELOG.md                                      |  6 +++++
 Cargo.lock                                        |  2 +-
 Cargo.toml                                        |  2 +-
 src/delivery.rs                                   | 31 ++++++++++++++++++++++
 src/git.rs                                        | 19 ++++++++-----
 src/hooks.rs                                      | 19 ++++++++++++-
 src/lib.rs                                        |  1 +
 src/main.rs                                       |  8 +++++-
 11 files changed, 99 insertions(+), 16 deletions(-)

git diff --no-index --stat /dev/null tests/adversary_published_merge.rs
 /dev/null => tests/adversary_published_merge.rs | 382 ++++++++++++++++++++++++
 1 file changed, 382 insertions(+)
```

Owners: the implementor owns the stable production Rust and its existing tests. The coordinator owns version 0.1.6, lockfile/changelog, planning, wave/report documentation, subsequent correction, integration and release. This adversary owns only the new untracked tests/adversary_published_merge.rs and assigned scratch outputs. The displayed whole-tree diff includes the other owners' pre-existing and concurrent disjoint work; it is not a reviewer-owned production diff. No implementation, existing test, AEP, specification or repository documentation was edited during this review. No commit, publication, or live repository mutation was performed.

Test file SHA256 at stable handback:
`96dbdddf4a2c162d70cdd1e46af6759184e39dbebbfebd1f55df4ce65fcac62b`.

## 1. New cases and targeted execution

The tests construct local synthetic Git objects and inject the authenticated-read boundary. They call both real publication and pre-push adapters. They do not replace the production GitHub client, contact a live delivery endpoint or claim to have forged authenticated GitHub responses.

The failing case was written first and executed alone before any suite run:
`cargo test --locked --test adversary_published_merge adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists -- --exact --nocapture`.
Exit 101; one executed, one behavioral failure, no compile failure:

```text
   Compiling b10x-gates v0.1.6 (<worktrees>/gates/ekr-gates-published-ancestry-20260922)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 1.68s
     Running tests/adversary_published_merge.rs (<cache>/b10x-target/ekr-gates-published-ancestry-20260922/debug/deps/adversary_published_merge-8100e32f9b880ddc)

running 1 test

thread 'adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists' (485453) panicked at tests/adversary_published_merge.rs:231:5:
incomplete proof lists admitted: ["publish: rules=true, omitted=null", "pre-push: rules=true, omitted=null", "publish: rules=true, omitted={}", "pre-push: rules=true, omitted={}", "publish: rules=true, omitted={\"id\":8,\"number\":2}", "pre-push: rules=true, omitted={\"id\":8,\"number\":2}", "publish: rules=false, omitted=null", "pre-push: rules=false, omitted=null", "publish: rules=false, omitted={}", "pre-push: rules=false, omitted={}", "publish: rules=false, omitted={\"id\":8,\"number\":2}", "pre-push: rules=false, omitted={\"id\":8,\"number\":2}"]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace
test adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists ... FAILED

failures:

failures:
    adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.31s

error: test failed, to rerun pass `--test adversary_published_merge`

```

The case first verifies each unmodified fixture succeeds through both adapters. It then appends one malformed entry beside the valid proof. Three variants—null, an empty object, and an object missing the discriminator—are each tried in both ruleset and associated-PR lists. All twelve adapter/list/variant observations were accepted, rather than the required refusal. The fixture reports every outcome before failing, so an early assertion cannot hide an unexecuted provider or variant.

Five additional cases were then written and each executed alone using the same command form, its full exact name and --exact --nocapture. Each exited 0 with one executed case before the full suite:

| Case | Measured control |
|---|---|
| adversary_unrelated_rules_and_explicit_null_unmerged_pr_remain_valid | A legitimate unrelated ruleset and associated open PR with explicit merge_commit_sha:null do not invalidate an otherwise valid proof. |
| adversary_published_merge_does_not_excuse_a_later_nonbot_committer | New non-bot commits after the authenticated merge refuse both as the candidate and as a side ancestor of an exact-bot join. |
| adversary_local_replacement_cannot_hide_a_nonbot_commit | A local replace ref mapping a bad commit to exact-bot bytes cannot override actual raw history. |
| adversary_remote_authority_is_not_reused_across_verification_calls | A subsequent call refuses disabled branch authority after an earlier successful verification. |
| adversary_duplicate_proof_on_later_page_is_not_ignored | A full first page with one valid proof and legitimate unrelated entries succeeds when page two is empty, then refuses when page two repeats the proof. Both list types and both adapters execute. |

The nullable control follows the public GitHub API model: pull-request-simple requires the merge_commit_sha key while permitting its value to be null. This is different from a missing key or a non-object list member. The schema projection was downloaded from the [official GitHub REST API description](https://github.com/github/rest-api-description/blob/main/descriptions/api.github.com/api.github.com.json) and retained as github-pr-list-schema.json. The [associated-PR endpoint documentation](https://docs.github.com/en/rest/commits/commits#list-pull-requests-associated-with-a-commit) also describes open and merged PR results. No private repository metadata was read.

## 2. Full suite after the six cases existed

Before=102 is the implementor's retained final executed count, not an adversary preemptive run. The new file adds six top-level tests. All 102 prior executed cases still pass; the new target runs five green and one red. Total: 108 executed, 107 passed, 1 failed, plus the same 7 existing ignored security cases. None were added, rewritten, skipped or unignored here.

Environment for every cargo test/clippy invocation:
- CARGO_TARGET_DIR=<cache>/b10x-target/ekr-gates-published-ancestry-20260922
- CARGO_BUILD_JOBS=2
- TMPDIR=<cache>/ekr-completion-20260922/gates-ancestry/adversary
- B10X_GATES_GITLEAKS pointed to the existing protected installation's pinned binary, discovered at the assigned configuration location.

Free disk was measured before builds: 19 GB initially and 18 GB before the full suite, above the assigned 10 GB floor.

Command: `cargo test --locked --no-fail-fast`
Exit 101. Full output, private path prefixes substituted:

```text
   Compiling b10x-gates v0.1.6 (<worktrees>/gates/ekr-gates-published-ancestry-20260922)
    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.90s
     Running unittests src/lib.rs (<cache>/b10x-target/ekr-gates-published-ancestry-20260922/debug/deps/b10x_gates-13b0a76375bd80b6)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running unittests src/main.rs (<cache>/b10x-target/ekr-gates-published-ancestry-20260922/debug/deps/b10x_gates-6c12380f45746d75)

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

     Running tests/adversary_published_merge.rs (<cache>/b10x-target/ekr-gates-published-ancestry-20260922/debug/deps/adversary_published_merge-8100e32f9b880ddc)

running 6 tests
test adversary_unrelated_rules_and_explicit_null_unmerged_pr_remain_valid ... ok
test adversary_remote_authority_is_not_reused_across_verification_calls ... ok
test adversary_local_replacement_cannot_hide_a_nonbot_commit ... ok
test adversary_duplicate_proof_on_later_page_is_not_ignored ... ok
test adversary_published_merge_does_not_excuse_a_later_nonbot_committer ... ok
test adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists ... FAILED

failures:

---- adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists stdout ----

thread 'adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists' (506539) panicked at tests/adversary_published_merge.rs:231:5:
incomplete proof lists admitted: ["publish: rules=true, omitted=null", "pre-push: rules=true, omitted=null", "publish: rules=true, omitted={}", "pre-push: rules=true, omitted={}", "publish: rules=true, omitted={\"id\":8,\"number\":2}", "pre-push: rules=true, omitted={\"id\":8,\"number\":2}", "publish: rules=false, omitted=null", "pre-push: rules=false, omitted=null", "publish: rules=false, omitted={}", "pre-push: rules=false, omitted={}", "publish: rules=false, omitted={\"id\":8,\"number\":2}", "pre-push: rules=false, omitted={\"id\":8,\"number\":2}"]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists

test result: FAILED. 5 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.32s

error: test failed, to rerun pass `--test adversary_published_merge`
     Running tests/published_merge.rs (<cache>/b10x-target/ekr-gates-published-ancestry-20260922/debug/deps/published_merge-e710c99b35eb1402)

running 61 tests
test head_outside_enrolled_history_refuses_even_with_exact_bot_identity ... ok
test direct_bot_delivery_needs_no_remote_exception ... ok
test authority_only_default_branch ... ok
test disabled_authority ... ok
test authority_excludes_branch ... ok
test api_unavailable ... ok
test fork_pr ... ok
test contradictory_private_repository ... ok
test invalid_signature_reason ... ok
test ambiguous_authority ... ok
test authority_missing_update_rule ... ok
test ambiguous_associated_pr ... ok
test default_ref_not_commit ... ok
test production_entrypoints_bind_shared_guard_before_delivery_and_receipt_reuse ... ok
test branch_with_slash_is_encoded_as_api_path_data ... ok
test merge_basis_must_already_be_in_pr_head ... ok
test local_merge_tree_must_equal_pr_head_tree ... ok
test missing_authority ... ok
test missing_associated_pr ... ok
test missing_default_branch ... ok
test missing_repository_identity ... ok
test nonpublic_repository ... ok
test missing_published_object ... ok
test redacted_authority ... ok
test nondefault_pr_target ... ok
test open_pr ... ok
test strict_direct_identity_applies_to_side_branch_ancestors ... ok
test direct_identity_rejects_duplicates_spoofs_and_malformed_dates ... ok
test unmerged_pr ... ok
test redacted_signature ... ok
test github_committer_exception_requires_exactly_two_parents ... ok
test published_bot_merge_allows_a_new_exact_bot_descendant ... ok
test unpublished_merge_despite_forged_local_remote_ref ... ok
test widened_authority ... ok
test wrong_authority_identity ... ok
test wrong_app ... ok
test unverified_signature ... ok
test wrong_default_ref ... ok
test wrong_pr_base_repository ... ok
test wrong_pr_base_repository_id ... ok
test wrong_pr_head ... ok
test wrong_pr_head_repository_id ... ok
test merge_raw_identity_cannot_be_overridden_by_remote_claims ... ok
test missing_local_parent_and_tree_objects_refuse ... ok
test nested_historical_merges_each_require_their_own_proof ... ok
test wrong_pr_merge ... ok
test wrong_pr_merge_actor ... ok
test wrong_remote_author_account ... ok
test wrong_pr_number ... ok
test wrong_remote_author_identity ... ok
test wrong_remote_committer_account ... ok
test wrong_remote_committer_identity ... ok
test wrong_remote_first_parent ... ok
test wrong_remote_merge_sha ... ok
test wrong_remote_second_parent ... ok
test wrong_repository_id ... ok
test wrong_remote_tree ... ok
test wrong_repository_name ... ok
test paginated_evidence_is_exhausted_before_admission ... ok
test pagination_limit_redaction_and_oversized_pages_fail_closed ... ok
test every_remote_read_is_required_and_missing_fields_fail_closed ... ok

test result: ok. 61 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.76s

     Running tests/security.rs (<cache>/b10x-target/ekr-gates-published-ancestry-20260922/debug/deps/security-d78029856067afc1)

running 48 tests
test a_home_path_behind_a_hyphen_or_an_underscore_is_caught ... ignored, DEFECT: the widened boundary class `[^a-z0-9._\-\\]` still excludes `-` and `_`, so a unified-diff removal line, a tight markdown bullet and `_..._` emphasis each hide a home path. `-` and `_` cannot end a hostname, so admitting them costs no false positive
test a_home_path_behind_an_invalid_utf8_byte_is_caught ... ignored, DEFECT: the boundary class is a Unicode class, so it cannot match a byte that is not valid UTF-8. One Latin-1 byte before the path hides it. Fix: wrap the class in `(?-u:)` so it is a byte class
test a_literal_carrying_invisible_or_confusable_characters_is_still_caught ... ignored, DEFECT: no Unicode confusable or invisible-character normalisation. A zero-width space, a soft hyphen, a Cyrillic homoglyph, a combining mark or a fullwidth letter each defeat the literal
test a_literal_in_a_utf16_unit_is_still_caught ... ignored, DEFECT: byte matching assumes UTF-8 or a superset of ASCII. A unit encoded UTF-16 carries the literal past every rule; Latin-1 is fine because the literal itself is ASCII
test a_literal_split_across_a_line_break_is_still_caught ... ignored, DEFECT: line-based scanning. All 30 interior split points of the literal evade; a soft-wrapped paragraph or a hyphenated line break carries the term out
test a_policy_whose_pattern_does_not_compile_is_refused_at_load ... ok
test an_allowance_does_not_admit_a_rule_it_was_not_written_for ... ignored, DEFECT: an allowance is not scoped to a rule. A citation allowance written for `private-identifiers` silently disables `personal-paths` inside its span, and a `file://` allowance is exactly the shape that covers a home path
test an_encoded_literal_is_still_caught ... ignored, DEFECT: no normalisation before matching. Percent, HTML-entity, JSON \u and base64 encodings of the literal all pass; base64 is not covered by Gitleaks either, whose decode depth only applies to its own secret rules
test a_forbidden_pattern_that_matches_everything_is_refused ... ok
test an_allowance_must_name_what_it_admits ... ok
test a_unc_user_profile_path_is_a_personal_path ... ok
test an_allowance_cannot_be_stretched_over_an_adjacent_use ... ok
test a_binary_unit_is_left_to_the_secret_scanner ... ok
test a_path_that_only_contains_the_word_home_is_not_a_personal_path ... ok
test a_line_the_previous_version_already_carried_is_not_introduced_by_this_change ... ok
test an_exception_may_cover_a_generated_tree_without_a_line_or_a_digest ... ok
test an_allowance_span_does_not_leak_onto_an_abutting_occurrence ... ok
test an_allowance_admits_only_what_its_match_contains ... ok
test authorship_refuses_bad_intermediate_and_merged_side_commits ... ok
test case_insensitivity_is_unicode_simple_folding_not_ascii_folding ... ok
test pattern_rules_require_the_second_policy_version ... ok
test an_intermediate_violation_cannot_be_hidden_by_a_later_deletion ... ok
test an_allowance_admits_only_its_named_group_never_the_text_around_it ... ok
test a_changed_baseline_and_history_replacement_are_refused ... ok
test a_rest_route_is_not_a_personal_path ... ok
test a_dependency_update_is_admitted_as_an_author_and_nothing_else_is ... ok
test the_basic_credential_encoder_matches_standard_base64 ... ok
test candidate_ignore_files_comments_and_unbounded_exceptions_do_not_disable_rules ... ok
test text_reports_every_line_that_breaks_a_rule ... ok
test annotated_tag_messages_identities_and_names_are_bound ... ok
test authorship_refuses_human_spoofed_and_duplicate_raw_authors ... ok
test index_is_scanned_independently_of_unstaged_content ... ok
test workflows_require_immutable_action_revisions_and_explicit_permissions ... ok
test filenames_messages_author_and_committer_are_scanned ... ok
test valid_reuse_performs_zero_scanner_invocations_even_with_no_scanner_available ... ok
test bare_home_directories_fail_and_portable_placeholders_pass ... ok
test authorship_admits_exact_automation_and_keeps_direct_delivery_strict ... ok
test a_literal_survives_every_delimiter_this_estate_writes ... ok
test home_paths_are_caught_in_every_delimiter_this_estate_writes ... ok
test hostile_fork_content_is_read_as_data_and_symlinks_are_not_followed ... ok
test receipt_rejects_tampering_wrong_repository_signer_policy_and_incomplete_results ... ok
test rebase_and_source_changes_invalidate_receipts ... ok
test an_allow_pattern_that_admits_everything_is_refused ... ok
test a_bounded_separator_class_catches_the_separators_it_was_bounded_for ... ok
test patterns_express_what_an_escaped_literal_cannot ... ok
test actual_gitleaks_cannot_be_disabled_by_candidate_config_or_comments_and_output_is_redacted ... ok
test span_containment_is_not_quadratic_in_line_length ... ok
test installed_hooks_preserve_worktree_hooks_and_scan_after_existing_mutations_without_atlas ... ok

test result: ok. 41 passed; 0 failed; 7 ignored; 0 measured; 0 filtered out; finished in 4.17s

   Doc-tests b10x_gates

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s

error: 1 target failed:
    `--test adversary_published_merge`

```

Other checks:
- `cargo clippy --all-targets --locked -- -D warnings`: exit 0, clippy.log.
- `cargo fmt --all --check`: exit 0, fmt.log.
- `git diff --check`: exit 0.
- No source guard was mutated or temporarily edited. The executable mutation is the API response data inside the new test.

## 3. Finding

| ID | Location | Category / severity | Verdict / origin | What was measured | What reaches it |
|---|---|---|---|---|---|
| G1 | src/published_merge.rs:168; equivalent PR filtering at :273 | contract-drift / blocker | CONFIRMED / undecided | Both adapters admit a valid proof accompanied by malformed or redacted list entries, twelve measured acceptance observations in one failing case. | Both production adapters call the shared verifier, which consumes authenticated API lists at this declared missing/redacted/ambiguous-evidence boundary. Filtering drops entries whose discriminator cannot be decoded before uniqueness is established. |

The rule and PR list filters treat an undecodable discriminator as a definite non-match. Therefore “exactly one matching proof” is established only after deleting the unknown entries from the evidence. The story and implementation report promise refusal for missing/redacted/ambiguous proof; this input class violates that stated contract.

This does not establish an unauthorized GitHub write, a way for a candidate repository to forge authenticated responses, or an observed live GitHub response containing these malformed entries. It establishes the missing promised refusal at the explicitly injectable authenticated-read boundary. The positive controls separately demonstrate that the valid historical exception does not excuse newly introduced non-bot history.

Origin remains undecided: the verification API is new in the dirty implementation, no assigned runnable base tree was available, and no base execution of this nonexistent API was performed. The source location alone is not reported as measured historical origin.

Required repair:
1. Validate the list-item shape and required selection/identity fields before filtering or proving uniqueness.
2. Ruleset entries must have usable typed identity and name; a missing/null/non-string name cannot stand for “unrelated.”
3. Associated PR entries must have usable typed identity and an explicitly present merge_commit_sha of the supported nullable/string shape. Missing is not null. Preserve explicit null for an unmerged/unrelated PR; do not require every associated PR to have merged.
4. Keep exact-one matching authority and matching merged PR, complete pagination, subsequent detailed checks, and both adapters' common verifier.
5. Preserve the new positive nullable control and existing legitimate unrelated/page controls. Do not “fix” this by rejecting every multi-entry list or discarding malformed entries with a warning.
6. Retain the new failing case unchanged: after correction it must pass, while the full lane should execute 108 passes with the same seven ignored cases.

One finding covers both list sites because they share the same omission-to-nonmatch failure class and the same measured correction contract.

## 4. Attacks that remained green

- Newly introduced non-bot history after a valid published merge still refuses on both direct and side ancestry.
- Local replace refs cannot change the raw identity checked by delivery.
- Remote authority is loaded afresh on subsequent verification calls.
- Matching proof duplicated on a later page invalidates uniqueness; full first-page unrelated entries remain supported.
- Explicit nullable PR merge SHA is supported alongside the actual merged proof.
- Existing source tests execute nested-merge proof ownership, exact raw identities, public repository identity, branch authority, default ref, signatures, parents/tree, PR actor/head/repository/target, missing objects, local-only merges, pagination completeness and both adapter bindings; all 61 remain green.
- Existing 41 executed security tests remain green, including no-scanner receipt reuse and coordinated hook behavior. Seven pre-existing ignored scanner defects remain explicitly ignored in runner output and are outside this unit.

These are synthetic injected-read and local Git observations. No live signature verification, GitHub source CI, release artifact check, publication or consumer adoption was executed in this review.

## 5. Outside paths and stable handback

Public report paths use <cache> and <worktrees>; raw logs retain exact local paths and stay private. The exact manifest is adjacent outside-paths.txt.

- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/proof-list-first.log`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/adversary_unrelated_rules_and_explicit_null_unmerged_pr_remain_valid.log`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/adversary_published_merge_does_not_excuse_a_later_nonbot_committer.log`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/adversary_local_replacement_cannot_hide_a_nonbot_commit.log`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/adversary_remote_authority_is_not_reused_across_verification_calls.log`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/adversary_duplicate_proof_on_later_page_is_not_ignored.log`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/full-suite.log`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/clippy.log`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/fmt.log`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/github-pr-list-schema.json`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/adversary-report.md`
- `<cache>/ekr-completion-20260922/gates-ancestry/adversary/outside-paths.txt`

Compiler output stayed under <cache>/b10x-target/ekr-gates-published-ancestry-20260922. Temporary synthetic repositories stayed under the assigned TMPDIR and used normal fixture lifetime cleanup. Public documentation was read through the browser and curl; the only downloaded file retained is the small selected public schema projection. The pinned scanner was read, not modified. The managed session codex-ekr-gates-adversary was maintained with worktree hook commands and is released at handback. No cleanup of worktrees or compiler caches occurred.

Source and tests are stable. No compiler process from this pass remains active. The coordinator owns recording, source correction and its further review.

```findings
- file: src/published_merge.rs
  line: 168
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: undecided
  message: Both adapters discard malformed or redacted ruleset and associated-PR list entries before establishing unique authenticated proof.
```

