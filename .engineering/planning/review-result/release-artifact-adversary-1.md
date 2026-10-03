---
format: aep.planning-md/3
id: review-result:release-artifact-adversary-1
kind: review-result
status: active
title: Executable artifact validation adversary pass 1
relations:
- reviews: story:release-artifact-validation
revision: 1
---
unit: release-artifact-validation at ca21c595071c4888619f746f5e6da79296a956e6 plus frozen author patch 360e6bdce8a2de030230c57b69783d338c418f1cfa29008a312217ebd42406ed
verdict: CONFIRMED
cases: executed 8→10, red 1
origin: introduced 1 / pre-existing 0 / undecided 0
wrote-outside-worktree: assigned review evidence, build target and temporary fixture directories; inventory below
needs-coordinator: correct all-program-header validation and rerun the frozen cases before artifact publication

1. Reviewer delta relative to handed snapshot

```
 /dev/null => tests/adversary_artifact.rs | 149 +++++++++++++++++++++++++++++++
 1 file changed, 149 insertions(+)
```

Only tests/adversary_artifact.rs was added by this reviewer. All author files were preexisting changes and their frozen source manifest verified unchanged both before and after execution. No production, existing test or planning-store file was edited. Author patch manifest SHA256: 812991c925ee10e0c127fcc1d45a62a770a95288dae697c86092f2697ffbc625.

Review file SHA256: 8979e6029d3d8f0f8e5b00639e37d7c48b48478ac8acd41024b3d952f98adc5d.
Tests-only patch SHA256: 8f28e2c051ad2d0519f859506c1a8741cf63ae01dbe16b32654b2255f62e5e50.

2. Cases written before execution

adversary_all_program_header_ranges_must_be_valid_before_scanning first accepts a synthetic ELF64 executable through artifact::validate, requiring exactly one scanner invocation. It then independently changes its program-header type to PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_NOTE and PT_TLS, with an impossible file offset. Each malformed input must refuse before scanning. The PT_LOAD case refuses correctly; all four other types succeed and invoke the scanner. The case was red on first execution.

Command: cargo test --locked --offline --test adversary_artifact adversary_all_program_header_ranges_must_be_valid_before_scanning -- --exact

```
   Compiling proc-macro2 v1.0.107
   Compiling quote v1.0.47
   Compiling unicode-ident v1.0.24
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
   Compiling yoke v0.8.3
   Compiling memchr v2.8.3
   Compiling zerovec v0.11.8
   Compiling itoa v1.0.18
   Compiling shlex v2.0.1
   Compiling bytes v1.12.1
   Compiling pin-project-lite v0.2.17
   Compiling find-msvc-tools v0.1.12
   Compiling cc v1.4.5
   Compiling futures-core v0.3.34
   Compiling tinystr v0.8.4
   Compiling getrandom v0.2.17
   Compiling version_check v0.9.5
   Compiling smallvec v1.16.0
   Compiling litemap v0.8.3
   Compiling writeable v0.6.4
   Compiling zeroize v1.9.0
   Compiling ring v0.17.14
   Compiling icu_locale_core v2.3.0
   Compiling generic-array v0.14.7
   Compiling potential_utf v0.1.6
   Compiling zerotrie v0.2.5
   Compiling mio v1.2.3
   Compiling socket2 v0.6.5
   Compiling icu_properties_data v2.3.0
   Compiling futures-sink v0.3.34
   Compiling once_cell v1.21.4
   Compiling serde_core v1.0.229
   Compiling icu_normalizer_data v2.3.0
   Compiling utf8_iter v1.0.4
   Compiling icu_collections v2.3.0
   Compiling tokio v1.53.1
   Compiling icu_provider v2.3.1
   Compiling http v1.5.0
   Compiling percent-encoding v2.3.2
   Compiling autocfg v1.5.1
   Compiling typenum v1.20.1
   Compiling untrusted v0.9.0
   Compiling num-traits v0.2.19
   Compiling http-body v1.1.0
   Compiling rustls-pki-types v1.15.1
   Compiling subtle v2.6.1
   Compiling futures-io v0.3.34
   Compiling serde v1.0.229
   Compiling slab v0.4.12
   Compiling httparse v1.10.1
   Compiling futures-task v0.3.34
   Compiling futures-util v0.3.34
   Compiling icu_normalizer v2.3.0
   Compiling icu_properties v2.3.0
   Compiling serde_derive v1.0.229
   Compiling base64 v0.22.1
   Compiling semver v1.0.28
   Compiling try-lock v0.2.5
   Compiling rustls v0.23.44
   Compiling tower-service v0.3.3
   Compiling zmij v1.0.23
   Compiling want v0.3.1
   Compiling rustc_version v0.4.1
   Compiling idna_adapter v1.2.2
   Compiling rustls-webpki v0.103.15
   Compiling block-buffer v0.10.4
   Compiling crypto-common v0.1.7
   Compiling form_urlencoded v1.2.2
   Compiling tracing-core v0.1.36
   Compiling futures-channel v0.3.34
   Compiling num-conv v0.2.2
   Compiling bitflags v2.13.2
   Compiling thiserror v2.0.20
   Compiling time-core v0.1.9
   Compiling serde_json v1.0.151
   Compiling atomic-waker v1.1.2
   Compiling utf8parse v0.2.2
   Compiling time-macros v0.2.32
   Compiling anstyle-parse v1.0.0
   Compiling hyper v1.11.1
   Compiling tracing v0.1.44
   Compiling digest v0.10.7
   Compiling num-integer v0.1.47
   Compiling idna v1.1.0
   Compiling curve25519-dalek v4.1.3
   Compiling sync_wrapper v1.0.2
   Compiling thiserror-impl v2.0.20
   Compiling rustix v1.1.4
   Compiling ryu v1.0.23
   Compiling anstyle-query v1.1.5
   Compiling ipnet v2.12.2
   Compiling colorchoice v1.0.5
   Compiling is_terminal_polyfill v1.70.2
   Compiling getrandom v0.4.3
   Compiling powerfmt v0.2.0
   Compiling deranged v0.5.8
   Compiling tower-layer v0.3.3
   Compiling anstyle v1.0.14
   Compiling cpufeatures v0.2.17
   Compiling anstream v1.0.0
   Compiling tower v0.5.3
   Compiling time v0.3.55
   Compiling tokio-rustls v0.26.5
   Compiling hyper-util v0.1.20
   Compiling url v2.5.8
   Compiling num-bigint v0.4.8
   Compiling webpki-roots v1.0.9
   Compiling aho-corasick v1.1.5
   Compiling curve25519-dalek-derive v0.1.1
   Compiling linux-raw-sys v0.12.1
   Compiling equivalent v1.0.2
   Compiling hashbrown v0.17.1
   Compiling heck v0.5.0
   Compiling regex-syntax v0.8.11
   Compiling strsim v0.11.1
   Compiling anyhow v1.0.104
   Compiling clap_lex v1.1.0
   Compiling signature v2.2.0
   Compiling ed25519 v2.2.3
   Compiling clap_builder v4.6.6
   Compiling regex-automata v0.4.18
   Compiling indexmap v2.14.2
   Compiling clap_derive v4.6.4
   Compiling simple_asn1 v0.6.4
   Compiling hyper-rustls v0.27.9
   Compiling tower-http v0.6.11
   Compiling sha2 v0.10.9
   Compiling serde_urlencoded v0.7.1
   Compiling pem v3.0.6
   Compiling http-body-util v0.1.5
   Compiling rand_core v0.6.4
   Compiling unsafe-libyaml v0.2.11
   Compiling fastrand v2.5.0
   Compiling log v0.4.34
   Compiling reqwest v0.12.28
   Compiling serde_yaml v0.9.34+deprecated
   Compiling tempfile v3.27.0
   Compiling ed25519-dalek v2.2.0
   Compiling jsonwebtoken v9.3.1
   Compiling clap v4.6.6
   Compiling regex v1.13.1
   Compiling object v0.40.0
   Compiling hex v0.4.3
   Compiling b10x-gates v0.1.12 ($WORKTREE)
    Finished `test` profile [unoptimized] target(s) in 38.55s
     Running tests/adversary_artifact.rs ($BUILD/debug/deps/adversary_artifact-ecbdf167d7ab0055)

running 1 test
test adversary_all_program_header_ranges_must_be_valid_before_scanning ... FAILED

failures:

---- adversary_all_program_header_ranges_must_be_valid_before_scanning stdout ----

thread 'adversary_all_program_header_ranges_must_be_valid_before_scanning' (3804297) panicked at tests/adversary_artifact.rs:111:5:
malformed file ranges reached successful scanning: ["program type 2: accepted=true, scanner_calls=1", "program type 3: accepted=true, scanner_calls=1", "program type 4: accepted=true, scanner_calls=1", "program type 7: accepted=true, scanner_calls=1"]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    adversary_all_program_header_ranges_must_be_valid_before_scanning

test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s

error: test failed, to rerun pass `--test adversary_artifact`
```
Exit status: 101.

adversary_digest_covers_unscanned_bytes_and_scanner_failure_propagates validates two artifacts with differing nonprintable overlay bytes, checks SHA256 against the entire original input, checks input byte count, requires distinct hashes, and observes one scanner call carrying the expected release metadata. A scanner error must propagate rather than produce success. Green on first execution.

Command: cargo test --locked --offline --test adversary_artifact adversary_digest_covers_unscanned_bytes_and_scanner_failure_propagates -- --exact

```
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Blocking waiting for file lock on package cache
    Finished `test` profile [unoptimized] target(s) in 1.73s
     Running tests/adversary_artifact.rs ($BUILD/debug/deps/adversary_artifact-ecbdf167d7ab0055)

running 1 test
test adversary_digest_covers_unscanned_bytes_and_scanner_failure_propagates ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s

```
Exit status: 0.

3. Combined targets after both cases

Command: cargo test --locked --offline --test artifact --test adversary_artifact --no-fail-fast

```
   Compiling b10x-gates v0.1.12 ($WORKTREE)
    Finished `test` profile [unoptimized] target(s) in 0.36s
     Running tests/adversary_artifact.rs ($BUILD/debug/deps/adversary_artifact-ecbdf167d7ab0055)

running 2 tests
test adversary_digest_covers_unscanned_bytes_and_scanner_failure_propagates ... ok
test adversary_all_program_header_ranges_must_be_valid_before_scanning ... FAILED

failures:

---- adversary_all_program_header_ranges_must_be_valid_before_scanning stdout ----

thread 'adversary_all_program_header_ranges_must_be_valid_before_scanning' (3813905) panicked at tests/adversary_artifact.rs:111:5:
malformed file ranges reached successful scanning: ["program type 2: accepted=true, scanner_calls=1", "program type 3: accepted=true, scanner_calls=1", "program type 4: accepted=true, scanner_calls=1", "program type 7: accepted=true, scanner_calls=1"]
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace


failures:
    adversary_all_program_header_ranges_must_be_valid_before_scanning

test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s

error: test failed, to rerun pass `--test adversary_artifact`
     Running tests/artifact.rs ($BUILD/debug/deps/artifact-18f4eb9a28079877)

running 8 tests
test missing_or_failing_secret_scanning_is_a_refusal ... ok
test unicode_format_characters_in_non_executable_data_cannot_split_a_private_identifier ... ok
test truncated_and_out_of_bounds_sections_are_refused_before_scanning ... ok
test executable_section_flags_do_not_hide_a_printable_identifier ... ok
test unsupported_and_incomplete_artifacts_are_refused_before_scanning ... ok
test private_identifiers_and_personal_paths_in_data_are_refused_without_echoing_them ... ok
test instruction_bytes_are_not_prose_but_the_complete_artifact_digest_is_reported ... ok
test the_real_pinned_scanner_refuses_a_synthetic_secret_even_in_an_executable_section ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.44s

error: 1 target failed:
    `--test adversary_artifact`
```
Exit status: 101. Nine passed, one failed, zero ignored. The before count of eight is the author's reported artifact target count; no suite was run before the new cases were written. All eight author cases passed here, including real pinned Gitleaks detection of synthetic secrets in executable sections. The two new library cases use an observing synthetic scanner, separately from those CLI cases.

Strict Clippy for the new test target and cargo fmt --all --check both passed. This reviewer did not run the entire repository gate or perform a source mutation. The introduced case itself remains red without mutation.

Build settings: CARGO_INCREMENTAL=0, CARGO_BUILD_JOBS=2, CARGO_PROFILE_DEV_DEBUG=0, CARGO_PROFILE_TEST_DEBUG=0, RUSTC_WRAPPER=; CARGO_TARGET_DIR=$BUILD; TMPDIR=$FIXTURES. CLI cases used B10X_GATES_GITLEAKS=$SCANNER. Initial available temporary storage was 15,001,726,976 bytes and available RAM 30,428,041,216 bytes; completion checks remained above both floors.

4. Finding

| File:line | Verdict | Origin | Severity | Finding |
|---|---|---|---|---|
| src/artifact.rs:183 | CONFIRMED | introduced | blocker | The artifact validator skips non-PT_LOAD program headers, accepting out-of-bounds PT_DYNAMIC, PT_INTERP, PT_NOTE and PT_TLS ranges and invoking the scanner despite its complete-inventory contract. |

Measured: tests/adversary_artifact.rs:111 reports four accepted malformed range variants with scanner_calls=1; first isolated and combined runs exit 101. The segment inventory count at src/artifact.rs:125 uses the same filtered iterator, though its numeric limit was not separately attacked in this pass.

Reaches: scan-artifact at src/main.rs:302 calls artifact::validate on the provided file without a preceding format guard. These are ordinary on-disk ELF inputs; no forged private policy, live credentials or candidate execution is needed. object 0.40.0's ElfSegmentIterator explicitly filters to PT_LOAD. Its raw elf_program_headers API exposes the complete table for a bounded correction. This new validator and command did not exist at the base; the defect is introduced by this patch, not an observed base failure.

5. Scope and limits

Could not break full-input digest binding, nonempty meaningful scanner input, or scanner-error propagation with the new control. Existing CLI cases continue detecting non-executable private identifiers and paths, executable long secrets, missing scanner, truncated sections and the Unicode-format regression. This is a bounded inventory review, not a general ELF security audit. The actual release artifact and corrected implementation still require validation; this report is not approval.

6. Outside-worktree inventory

Retained evidence directory: $REVIEW
Explicit build directory: $BUILD
Explicit temporary fixture directory: $FIXTURES (tempfile-managed fixtures dropped by tests).

Files retained in the evidence directory:
- $REVIEW/ranges.log
- $REVIEW/ranges.exit
- $REVIEW/digest.log
- $REVIEW/digest.exit
- $REVIEW/suite.log
- $REVIEW/suite.exit
- $REVIEW/clippy.log
- $REVIEW/clippy.exit
- $REVIEW/fmt.log
- $REVIEW/fmt.exit
- $REVIEW/frozen-check.log
- $REVIEW/adversary.patch
- $REVIEW/report.raw.md
- $REVIEW/report.public.md
- $REVIEW/evidence.sha256

The public copy normalizes assigned local prefixes to $WORKTREE, $REVIEW, $BUILD, $FIXTURES and $SCANNER. Raw output remains retained verbatim in the raw report and logs. No private policy was read. Reviewer lease gates-artifact-adversary-20261003 is released on return. No commit, push, public action or cleanup was performed; the frozen pass-one source remains unchanged for reproduction.

```findings
- file: src/artifact.rs
  line: 183
  category: contract-drift
  severity: blocker
  verdict: CONFIRMED
  origin: introduced
  message: The artifact validator skips non-PT_LOAD program headers, accepting out-of-bounds PT_DYNAMIC, PT_INTERP, PT_NOTE and PT_TLS ranges and invoking the scanner despite its complete-inventory contract.
```
