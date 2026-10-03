---
format: aep.planning-md/3
id: review-result:github-update-branch-adversary-1
kind: review-result
status: active
title: Adversarial review of exact GitHub update-branch provenance
relations:
- reviews: story:github-update-branch-provenance
revision: 1
---
unit: github-update-branch-provenance; base 45b5b95234af42989aae41e496fb734476faf0ba plus frozen author patch and additive adversary tests
verdict: nothing found
cases: executed 76→79, red 0
origin: introduced 0 / pre-existing 0 / undecided 0
wrote-outside-worktree: 19 retained files in assigned scratch; temporary fixtures in assigned short-path directory
needs-coordinator: integrate additive tests and run final combined release gates; no approval asserted

1. Test-only diff relative to handed snapshot

```
 tests/adversary_published_merge.rs | 156 +++++++++++++++++++++++++++++++++++++
 1 file changed, 156 insertions(+)
```

The handed tree was already dirty in src/published_merge.rs and tests/published_merge.rs. Those are the author's frozen patch, not this reviewer's changes. SHA256 verification passed before and after this pass:

- src/published_merge.rs: 6aa0eb8e1a566f3d9b93ee13d1c482676dcaf6ed14a0cd4a3928f0a0013d45cd
- tests/published_merge.rs: 15f7551a5b3619b5ef21c21e38634fda04c4d67e4ba0892b4cf3cb4fa66b4789
- Final tests/adversary_published_merge.rs: e6a074ede1495b85cf4b6261a24f0691e70012b84116bd2badf5c5c0c07ea616
- Review-only adversary.patch: 3bdbce4db85c130aa5ae20052829f87ed7ab3dc3601aaa6f6fb64f606753927f

Only 156 lines were added to tests/adversary_published_merge.rs. No existing assertion was changed, skipped or deleted. The before count comes from the author's reported 70 published_merge and 6 existing adversary cases, not an early reviewer suite run.

2. Cases added before any test execution

All three tests call both verify_publication and verify_pre_push with synthetic authenticated-read responses and real local Git objects. A separate update fixture was built using the existing adversary fixture rather than the author's UpdateFixture.

- adversary_update_proof_never_excuses_a_nonbot_side_ancestor: first accepts an authenticated U=[P,B], M=[B,U] control, then inserts a nonbot side ancestor behind a bot merge in P. Both adapters must refuse specifically for committer identity, rather than absent fixture evidence.
- adversary_update_and_terminal_pagination_cannot_hide_incomplete_or_ambiguous_proof: for both U and M, a 100-entry first page plus empty second page passes; then missing page, duplicate proof, malformed record and another completed association on page two each refuse. Eight negative variants, each through both adapters.
- adversary_each_update_and_terminal_commit_identity_field_is_required: removes each of twelve identity/signature/tree/parent fields independently on U and M. Twenty-four negative variants, each through both adapters with a passing control before mutation.

All were green on first execution; no red output exists. The chronological individual commands and raw output follow. All cargo commands used CARGO_INCREMENTAL=0, CARGO_BUILD_JOBS=2, CARGO_PROFILE_DEV_DEBUG=0, CARGO_PROFILE_TEST_DEBUG=0, RUSTC_WRAPPER= and TMPDIR=$FIXTURES; CARGO_TARGET_DIR was unset.

Command: cargo test --locked --offline --test adversary_published_merge adversary_update_proof_never_excuses_a_nonbot_side_ancestor -- --exact

```
   Compiling proc-macro2 v1.0.107
   Compiling unicode-ident v1.0.24
   Compiling quote v1.0.47
   Compiling libc v0.2.189
   Compiling syn v3.0.5
   Compiling syn v2.0.119
   Compiling synstructure v0.13.2
   Compiling stable_deref_trait v1.2.1
   Compiling cfg-if v1.0.4
   Compiling zerovec-derive v0.11.6
   Compiling zerofrom-derive v0.1.7
   Compiling yoke-derive v0.8.2
   Compiling zerofrom v0.1.8
   Compiling displaydoc v0.2.7
   Compiling itoa v1.0.18
   Compiling yoke v0.8.3
   Compiling find-msvc-tools v0.1.12
   Compiling zerovec v0.11.8
   Compiling memchr v2.8.3
   Compiling bytes v1.12.1
   Compiling shlex v2.0.1
   Compiling pin-project-lite v0.2.17
   Compiling cc v1.4.5
   Compiling futures-core v0.3.34
   Compiling tinystr v0.8.4
   Compiling getrandom v0.2.17
   Compiling writeable v0.6.4
   Compiling smallvec v1.16.0
   Compiling litemap v0.8.3
   Compiling zeroize v1.9.0
   Compiling version_check v0.9.5
   Compiling generic-array v0.14.7
   Compiling icu_locale_core v2.3.0
   Compiling ring v0.17.14
   Compiling potential_utf v0.1.6
   Compiling zerotrie v0.2.5
   Compiling socket2 v0.6.5
   Compiling mio v1.2.3
   Compiling once_cell v1.21.4
   Compiling futures-sink v0.3.34
   Compiling icu_normalizer_data v2.3.0
   Compiling serde_core v1.0.229
   Compiling utf8_iter v1.0.4
   Compiling icu_properties_data v2.3.0
   Compiling icu_collections v2.3.0
   Compiling tokio v1.53.1
   Compiling icu_provider v2.3.1
   Compiling http v1.5.0
   Compiling untrusted v0.9.0
   Compiling autocfg v1.5.1
   Compiling percent-encoding v2.3.2
   Compiling typenum v1.20.1
   Compiling num-traits v0.2.19
   Compiling http-body v1.1.0
   Compiling rustls-pki-types v1.15.1
   Compiling futures-io v0.3.34
   Compiling httparse v1.10.1
   Compiling futures-task v0.3.34
   Compiling subtle v2.6.1
   Compiling serde v1.0.229
   Compiling slab v0.4.12
   Compiling futures-util v0.3.34
   Compiling icu_properties v2.3.0
   Compiling icu_normalizer v2.3.0
   Compiling serde_derive v1.0.229
   Compiling zmij v1.0.23
   Compiling rustls v0.23.44
   Compiling semver v1.0.28
   Compiling try-lock v0.2.5
   Compiling base64 v0.22.1
   Compiling tower-service v0.3.3
   Compiling want v0.3.1
   Compiling rustc_version v0.4.1
   Compiling idna_adapter v1.2.2
   Compiling rustls-webpki v0.103.15
   Compiling block-buffer v0.10.4
   Compiling crypto-common v0.1.7
   Compiling form_urlencoded v1.2.2
   Compiling futures-channel v0.3.34
   Compiling tracing-core v0.1.36
   Compiling serde_json v1.0.151
   Compiling atomic-waker v1.1.2
   Compiling thiserror v2.0.20
   Compiling bitflags v2.13.2
   Compiling num-conv v0.2.2
   Compiling utf8parse v0.2.2
   Compiling time-core v0.1.9
   Compiling anstyle-parse v1.0.0
   Compiling time-macros v0.2.32
   Compiling tracing v0.1.44
   Compiling hyper v1.11.1
   Compiling digest v0.10.7
   Compiling idna v1.1.0
   Compiling num-integer v0.1.47
   Compiling curve25519-dalek v4.1.3
   Compiling sync_wrapper v1.0.2
   Compiling thiserror-impl v2.0.20
   Compiling tower-layer v0.3.3
   Compiling anstyle-query v1.1.5
   Compiling colorchoice v1.0.5
   Compiling is_terminal_polyfill v1.70.2
   Compiling anstyle v1.0.14
   Compiling ryu v1.0.23
   Compiling getrandom v0.4.3
   Compiling rustix v1.1.4
   Compiling ipnet v2.12.2
   Compiling deranged v0.5.8
   Compiling powerfmt v0.2.0
   Compiling cpufeatures v0.2.17
   Compiling time v0.3.55
   Compiling hyper-util v0.1.20
   Compiling tokio-rustls v0.26.5
   Compiling anstream v1.0.0
   Compiling tower v0.5.3
   Compiling num-bigint v0.4.8
   Compiling url v2.5.8
   Compiling webpki-roots v1.0.9
   Compiling aho-corasick v1.1.5
   Compiling curve25519-dalek-derive v0.1.1
   Compiling linux-raw-sys v0.12.1
   Compiling anyhow v1.0.104
   Compiling heck v0.5.0
   Compiling hashbrown v0.17.1
   Compiling equivalent v1.0.2
   Compiling signature v2.2.0
   Compiling strsim v0.11.1
   Compiling regex-syntax v0.8.11
   Compiling clap_lex v1.1.0
   Compiling clap_builder v4.6.6
   Compiling regex-automata v0.4.18
   Compiling ed25519 v2.2.3
   Compiling indexmap v2.14.2
   Compiling clap_derive v4.6.4
   Compiling hyper-rustls v0.27.9
   Compiling tower-http v0.6.11
   Compiling simple_asn1 v0.6.4
   Compiling sha2 v0.10.9
   Compiling serde_urlencoded v0.7.1
   Compiling pem v3.0.6
   Compiling http-body-util v0.1.5
   Compiling rand_core v0.6.4
   Compiling log v0.4.34
   Compiling unsafe-libyaml v0.2.11
   Compiling fastrand v2.5.0
   Compiling tempfile v3.27.0
   Compiling reqwest v0.12.28
   Compiling serde_yaml v0.9.34+deprecated
   Compiling ed25519-dalek v2.2.0
   Compiling jsonwebtoken v9.3.1
   Compiling clap v4.6.6
   Compiling regex v1.13.1
   Compiling hex v0.4.3
   Compiling b10x-gates v0.1.11 ($WORKTREE)
    Finished `test` profile [unoptimized] target(s) in 42.78s
     Running tests/adversary_published_merge.rs (target/debug/deps/adversary_published_merge-a0b2024f20892b75)

running 1 test
test adversary_update_proof_never_excuses_a_nonbot_side_ancestor ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 0.16s

```
Exit status: 0

Command: cargo test --locked --offline --test adversary_published_merge adversary_update_and_terminal_pagination_cannot_hide_incomplete_or_ambiguous_proof -- --exact

```
    Finished `test` profile [unoptimized] target(s) in 0.21s
     Running tests/adversary_published_merge.rs (target/debug/deps/adversary_published_merge-a0b2024f20892b75)

running 1 test
test adversary_update_and_terminal_pagination_cannot_hide_incomplete_or_ambiguous_proof ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 2.37s

```
Exit status: 0

Command: cargo test --locked --offline --test adversary_published_merge adversary_each_update_and_terminal_commit_identity_field_is_required -- --exact

```
    Finished `test` profile [unoptimized] target(s) in 0.11s
     Running tests/adversary_published_merge.rs (target/debug/deps/adversary_published_merge-a0b2024f20892b75)

running 1 test
test adversary_each_update_and_terminal_commit_identity_field_is_required ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 8 filtered out; finished in 3.57s

```
Exit status: 0

3. Combined target suite, after all individual cases

Command: cargo test --locked --offline --test adversary_published_merge --test published_merge

```
   Compiling b10x-gates v0.1.11 ($WORKTREE)
    Finished `test` profile [unoptimized] target(s) in 0.76s
     Running tests/adversary_published_merge.rs (target/debug/deps/adversary_published_merge-a0b2024f20892b75)

running 9 tests
test adversary_unrelated_rules_and_explicit_null_unmerged_pr_remain_valid ... ok
test adversary_remote_authority_is_not_reused_across_verification_calls ... ok
test adversary_local_replacement_cannot_hide_a_nonbot_commit ... ok
test adversary_update_proof_never_excuses_a_nonbot_side_ancestor ... ok
test adversary_duplicate_proof_on_later_page_is_not_ignored ... ok
test adversary_published_merge_does_not_excuse_a_later_nonbot_committer ... ok
test adversary_malformed_entries_cannot_be_discarded_from_unique_proof_lists ... ok
test adversary_update_and_terminal_pagination_cannot_hide_incomplete_or_ambiguous_proof ... ok
test adversary_each_update_and_terminal_commit_identity_field_is_required ... ok

test result: ok. 9 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.37s

     Running tests/published_merge.rs (target/debug/deps/published_merge-081e6d53c0abedce)

running 70 tests
test direct_bot_delivery_needs_no_remote_exception ... ok
test head_outside_enrolled_history_refuses_even_with_exact_bot_identity ... ok
test a_squash_merge_is_admitted_on_shape_and_still_proved_against_the_remote ... ok
test default_ref_not_commit ... ok
test api_unavailable ... ok
test authority_missing_update_rule ... ok
test contradictory_private_repository ... ok
test authority_only_default_branch ... ok
test fork_pr ... ok
test ambiguous_authority ... ok
test disabled_authority ... ok
test branch_with_slash_is_encoded_as_api_path_data ... ok
test authority_excludes_branch ... ok
test ambiguous_associated_pr ... ok
test github_committer_exception_requires_one_or_two_parents ... ok
test invalid_signature_reason ... ok
test a_stale_basis_that_added_nothing_is_admitted ... ok
test direct_identity_rejects_duplicates_spoofs_and_malformed_dates ... ok
test production_entrypoints_bind_shared_guard_before_delivery_and_receipt_reuse ... ok
test local_merge_tree_must_equal_pr_head_tree ... ok
test missing_default_branch ... ok
test missing_authority ... ok
test missing_associated_pr ... ok
test nonpublic_repository ... ok
test missing_published_object ... ok
test missing_repository_identity ... ok
test open_pr ... ok
test nondefault_pr_target ... ok
test exact_update_branch_then_final_merge_is_admitted_by_both_entrypoints ... ok
test merge_basis_must_already_be_in_pr_head ... ok
test strict_direct_identity_applies_to_side_branch_ancestors ... ok
test redacted_authority ... ok
test unpublished_merge_despite_forged_local_remote_ref ... ok
test redacted_signature ... ok
test published_bot_merge_allows_a_new_exact_bot_descendant ... ok
test unmerged_pr ... ok
test unverified_signature ... ok
test merge_raw_identity_cannot_be_overridden_by_remote_claims ... ok
test widened_authority ... ok
test missing_local_parent_and_tree_objects_refuse ... ok
test wrong_app ... ok
test nested_historical_merges_each_require_their_own_proof ... ok
test wrong_authority_identity ... ok
test missing_local_update_graph_objects_refuse ... ok
test wrong_default_ref ... ok
test wrong_pr_base_repository_id ... ok
test wrong_pr_base_repository ... ok
test wrong_pr_head_repository_id ... ok
test wrong_pr_head ... ok
test wrong_pr_merge_actor ... ok
test wrong_pr_merge ... ok
test wrong_pr_number ... ok
test wrong_remote_author_account ... ok
test wrong_remote_author_identity ... ok
test wrong_remote_committer_account ... ok
test wrong_remote_committer_identity ... ok
test wrong_remote_merge_sha ... ok
test wrong_repository_id ... ok
test wrong_remote_first_parent ... ok
test wrong_remote_second_parent ... ok
test wrong_remote_tree ... ok
test wrong_repository_name ... ok
test paginated_evidence_is_exhausted_before_admission ... ok
test update_branch_associations_are_complete_unique_and_exhaustive ... ok
test pagination_limit_redaction_and_oversized_pages_fail_closed ... ok
test unsupported_update_branch_shapes_refuse ... ok
test update_branch_local_and_remote_commit_identity_is_exact ... ok
test update_branch_pull_request_summary_and_detail_are_bound ... ok
test every_remote_read_is_required_and_missing_fields_fail_closed ... ok
test final_merge_is_exactly_authenticated_and_bound_to_the_same_pull_request ... ok

test result: ok. 70 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.55s

```
Exit status: 0. Executed 9 adversary and 70 published_merge cases: 79 passed, 0 failed, 0 ignored.

Additional checks: cargo fmt --all --check passed after formatting only the added test code. Strict test-target Clippy passed:

Command: cargo clippy --locked --offline --test adversary_published_merge -- -D warnings

```
    Checking libc v0.2.189
    Checking zerofrom v0.1.8
    Checking stable_deref_trait v1.2.1
    Checking yoke v0.8.3
    Checking cfg-if v1.0.4
    Checking zerovec v0.11.8
    Checking itoa v1.0.18
    Checking memchr v2.8.3
    Checking bytes v1.12.1
    Checking pin-project-lite v0.2.17
    Checking futures-core v0.3.34
    Checking getrandom v0.2.17
    Checking tinystr v0.8.4
    Checking litemap v0.8.3
    Checking writeable v0.6.4
    Checking zeroize v1.9.0
    Checking smallvec v1.16.0
    Checking icu_locale_core v2.3.0
    Checking mio v1.2.3
    Checking socket2 v0.6.5
    Checking zerotrie v0.2.5
    Checking potential_utf v0.1.6
    Checking utf8_iter v1.0.4
    Checking futures-sink v0.3.34
    Checking once_cell v1.21.4
    Checking icu_provider v2.3.1
    Checking icu_collections v2.3.0
    Checking tokio v1.53.1
    Checking http v1.5.0
    Checking typenum v1.20.1
    Checking untrusted v0.9.0
    Checking percent-encoding v2.3.2
    Checking ring v0.17.14
    Checking generic-array v0.14.7
    Checking http-body v1.1.0
    Checking serde_core v1.0.229
    Checking icu_normalizer_data v2.3.0
    Checking icu_properties_data v2.3.0
    Checking rustls-pki-types v1.15.1
    Checking slab v0.4.12
    Checking futures-task v0.3.34
    Checking futures-io v0.3.34
    Checking subtle v2.6.1
    Checking futures-util v0.3.34
    Checking icu_properties v2.3.0
    Checking icu_normalizer v2.3.0
    Checking tower-service v0.3.3
    Checking base64 v0.22.1
    Checking try-lock v0.2.5
    Checking want v0.3.1
    Checking idna_adapter v1.2.2
    Checking serde v1.0.229
    Checking num-traits v0.2.19
    Checking httparse v1.10.1
    Checking rustls-webpki v0.103.15
    Checking block-buffer v0.10.4
    Checking crypto-common v0.1.7
    Checking form_urlencoded v1.2.2
    Checking tracing-core v0.1.36
    Checking futures-channel v0.3.34
    Checking bitflags v2.13.2
    Checking atomic-waker v1.1.2
    Checking utf8parse v0.2.2
    Checking hyper v1.11.1
    Checking anstyle-parse v1.0.0
    Checking tracing v0.1.44
    Checking rustls v0.23.44
    Checking digest v0.10.7
    Checking num-integer v0.1.47
    Checking idna v1.1.0
    Checking zmij v1.0.23
    Checking sync_wrapper v1.0.2
    Checking tower-layer v0.3.3
    Checking anstyle v1.0.14
    Checking time-core v0.1.9
    Checking is_terminal_polyfill v1.70.2
    Checking num-conv v0.2.2
    Checking deranged v0.5.8
    Checking cpufeatures v0.2.17
    Checking ipnet v2.12.2
    Checking colorchoice v1.0.5
    Checking ryu v1.0.23
    Checking anstyle-query v1.1.5
    Checking powerfmt v0.2.0
    Checking anstream v1.0.0
    Checking time v0.3.55
    Checking hyper-util v0.1.20
    Checking tokio-rustls v0.26.5
    Checking tower v0.5.3
    Checking thiserror v2.0.20
    Checking serde_json v1.0.151
    Checking url v2.5.8
    Checking num-bigint v0.4.8
    Checking webpki-roots v1.0.9
    Checking aho-corasick v1.1.5
    Checking clap_lex v1.1.0
    Checking linux-raw-sys v0.12.1
    Checking equivalent v1.0.2
    Checking hashbrown v0.17.1
    Checking regex-syntax v0.8.11
    Checking signature v2.2.0
    Checking strsim v0.11.1
    Checking clap_builder v4.6.6
    Checking regex-automata v0.4.18
    Checking ed25519 v2.2.3
    Checking indexmap v2.14.2
    Checking rustix v1.1.4
    Checking simple_asn1 v0.6.4
    Checking curve25519-dalek v4.1.3
    Checking hyper-rustls v0.27.9
    Checking tower-http v0.6.11
    Checking getrandom v0.4.3
    Checking serde_urlencoded v0.7.1
    Checking sha2 v0.10.9
    Checking pem v3.0.6
    Checking http-body-util v0.1.5
    Checking rand_core v0.6.4
    Checking unsafe-libyaml v0.2.11
    Checking log v0.4.34
    Checking fastrand v2.5.0
    Checking tempfile v3.27.0
    Checking reqwest v0.12.28
    Checking serde_yaml v0.9.34+deprecated
    Checking ed25519-dalek v2.2.0
    Checking jsonwebtoken v9.3.1
    Checking anyhow v1.0.104
    Checking clap v4.6.6
    Checking regex v1.13.1
    Checking hex v0.4.3
    Checking b10x-gates v0.1.11 ($WORKTREE)
    Finished `dev` profile [unoptimized] target(s) in 14.88s
```
Exit status: 0. Disk was checked before building and during verification: 16,352,628,736 initially and 12,552,343,552 bytes available near completion, above the 10 GiB floor.

4. Findings

Nothing found in this bounded pass. No judgement finding or approval is asserted. There was no failure requiring classification on the base.

5. Tested and untested scope

Read the active story, complete author patch and both production adapters. The shared DAG verifier remains called by publication and pre-push. The new cases could not break side-ancestor identity checking, exhaustive association pagination for either update or terminal proof, or mandatory remote identity/signature/tree/parent fields. All 70 author target cases also passed here, including supported update graph, unsupported shapes and existing ordinary merges.

This reviewer did not rerun the full repository suite, perform another source mutation, contact live GitHub or prove the actual ESS publication succeeds. Author-reported full-suite and guard-removal mutation results remain separately retained author evidence; they are not reviewer executions. Final delivered-tool and combined release verification remain outstanding. The inherited model identifier was not exposed to this reviewer and could not be confirmed.

6. Outside-worktree paths

Assigned scratch: $SCRATCH
Assigned transient fixture directory: $FIXTURES (tempfile-owned Git fixture directories were created and dropped by the cases).

Retained files, each under the assigned scratch directory:
- $SCRATCH/handed-adversary.rs
- $SCRATCH/format-initial.log
- $SCRATCH/side.log
- $SCRATCH/side.exit
- $SCRATCH/pages.log
- $SCRATCH/pages.exit
- $SCRATCH/identity.log
- $SCRATCH/identity.exit
- $SCRATCH/suite.log
- $SCRATCH/suite.exit
- $SCRATCH/fmt.log
- $SCRATCH/fmt.exit
- $SCRATCH/frozen-source-check.log
- $SCRATCH/adversary.patch
- $SCRATCH/clippy.log
- $SCRATCH/clippy.exit
- $SCRATCH/report.raw.md
- $SCRATCH/report.public.md
- $SCRATCH/evidence.sha256

No private policy, credentials, AEP record, production source, author test source, commit, push or cleanup was changed. The assigned checkout's own target directory was used. Reviewer lease gates-update-adversary-20261003 is released on return; the coordinator owns tree lifecycle.

The publication-safe copy normalizes only the assigned worktree, evidence-cache and fixture prefixes to $WORKTREE, $SCRATCH and $FIXTURES. Raw logs and report preserve local paths and original output. evidence.sha256 binds the retained snapshot, patch, logs and reports.

```findings
[]
```
