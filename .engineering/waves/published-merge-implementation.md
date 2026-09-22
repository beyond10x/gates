unit: story:published-merge-delivery — authenticated historical App merge ancestry
verdict: green
cases: executed 41→102, red 0; 7 existing ignored cases unchanged
origin: n/a
wrote-outside-worktree: assigned scratch and Cargo target; managed lease metadata through worktree CLI
needs-coordinator: independent adversary, integration gate, source CI, release and authenticated consumer verification

The unit is stable and uncommitted on `codex/ekr-gates-published-ancestry-20260922`, opening `270c2903bb42b3d3018dd90d0a99aeb93a9c5772`. No inherited uncommitted source/test changes existed. All seven changed Rust files are authored here. No source process remains running at handback. The implementor's lease is released after preserving this report.

## Change and boundary

Both CLI publication and the installed pre-push path call one ancestry verifier. It derives the entire DAG after the enrolled baseline itself, including side branches. Exact bot author and committer remain sufficient for direct commits. The exact identity parser now also rejects duplicate headers and malformed timestamps; commit-time checks are unchanged.

A different committer can qualify only as an exact raw bot-authored, exact GitHub-committed, two-parent merge. Authenticated GitHub reads must establish the enrolled numeric repository identity and full name, public visibility, exact active App-only authority across every branch, the current default-branch object and merge reachability, exact remote identities and verified signature, agreement with both local parents and tree, and one merged same-repository PR into the default branch merged by the exact organization bot. Its head must equal the second parent, include the first parent, and have the merge tree. Each nested merge requires its own proof. Local tracking refs and message claims have no role.

The production reader uses the existing fixed-host authenticated GitHub client. Hooks acquire remote evidence lazily from the credential already passed by bot delivery; ordinary direct commits make no API request. Missing credentials, read failure, missing/redacted fields, ambiguous lists, incomplete pagination, unavailable local objects and mismatched evidence refuse. Repository and authority evidence is held only for the current verification call. There is no persistent trust cache, policy/baseline change, protection write, bypass flag, runtime dependency or candidate execution.

## Scope observed by Git

Tracked diff:

```text
 src/delivery.rs | 31 +++++++++++++++++++++++++++++++
 src/git.rs      | 19 ++++++++++++-------
 src/hooks.rs    | 19 ++++++++++++++++++-
 src/lib.rs      |  1 +
 src/main.rs     |  8 +++++++-
 5 files changed, 69 insertions(+), 9 deletions(-)
```

New untracked files: `src/published_merge.rs` (325 lines), `tests/published_merge.rs` (892 lines). Complete tracked/new-file patches and all seven file digests are retained in assigned scratch as `authored-*.patch` and `source-sha256.txt`. Existing `tests/security.rs` is unchanged.

## Measured execution

Commands ran in the assigned unit with `CARGO_BUILD_JOBS=2`, assigned `CARGO_TARGET_DIR` and assigned scratch as `TMPDIR`. Full-suite commands additionally set `B10X_GATES_GITLEAKS` to the existing pinned 8.30.1 binary. Full paths are intentionally excluded from this public-ready report; the wave page owns those assignments.

The first unconfigured baseline returned exit 101 because two existing scanner tests require the pinned binary environment variable. `baseline.log` preserves that evidence. After supplying it, the unchanged source passed (`baseline-configured.log`, exit 0):

```text
$ cargo test --locked
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 41 passed; 0 failed; 7 ignored; 0 measured; 0 filtered out; finished in 4.13s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

The new positive case first ran against the original strict behavior through a staged compiling API. It failed behaviorally (`red-first.log`, exit 101):

```text
$ cargo test --locked --test published_merge published_bot_merge_allows_a_new_exact_bot_descendant -- --exact
running 1 test
test published_bot_merge_allows_a_new_exact_bot_descendant ... FAILED
authenticated historical merge must be admitted: Err(outgoing commit must have the exact bot author and committer)
test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
```

After restoring every mutation, final full suite (`full-final.log`, exit 0):

```text
$ cargo test --locked
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
test result: ok. 61 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.77s
test result: ok. 41 passed; 0 failed; 7 ignored; 0 measured; 0 filtered out; finished in 4.14s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
```

Same full-suite command: executed 41→102, exit 0. Existing security lane: 41→41, with the same seven ignored cases. The new integration target did not exist on the base; its observed first execution was 1 red and its final execution was 61 green. No base execution of that nonexistent target is claimed.

```text
$ cargo fmt --all --check
[no output; exit 0]
$ cargo clippy --all-targets --locked -- -D warnings
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.88s
[exit 0]
$ git diff --check
[no output; exit 0]
```

`fmt.log` and `clippy-final.log` retain full output. An earlier Clippy warning about constructing a slice from a cloned test ID was corrected. Earlier fixture-construction failures and development logs remain retained, including Git's refusal to construct deliberately malformed duplicate headers without `hash-object --literally`. The missing-tree fixture uses a nonempty tree because Git can synthesize its special empty tree without a loose object.

The installed privacy scanner, explicitly given the existing protected policy, scanned all seven source/test files and this public-ready report: `8 file(s) carry no private rule`, exit 0 (`privacy-final.log`). Its first invocation without that policy argument refused because the default protected file was unavailable; nothing was changed to resolve that beyond selecting the existing policy. Raw private-path logs stay in assigned scratch.

## Mutation evidence and acceptance quality

Thirty source guard mutations and four publication wiring mutations each returned exit 101 with exactly one executed behavioral failure. The harness rejected compilation failures, zero selected tests and surviving mutations. Every mutation was restored before the final full gate. `mutations.rs`, `wiring-mutations.rs`, `mutations-complete.log`, `wiring-mutations.log` and individual `mutation-*.log` files retain commands and outputs.

The proof sweep removed raw author/committer checks, the two-parent constraint, repository identity/public visibility, authority uniqueness/identity/exactness, default-ref identity, remote commit identity/author/committer/signature/parents/tree, PR uniqueness/identity/completion/actor/repository/target/head, accepted-tree equality, published reachability, first-parent ancestry, enrolled ancestry, complete pagination, full-DAG direct checks and unique exact raw identities. Wiring mutations removed each shared verifier call and each actual entrypoint call. Entry-point binding cases read the executing checkout via runtime `CARGO_MANIFEST_DIR`; injected API cases exercise both publication adapters against the same synthetic Git histories.

The first parent-count mutation survived. Its fixture accidentally overwrote an earlier merge's PR detail, allowing a different refusal to mask the shape check. The corrected fixture uses an independent direct third parent and asserts the named two-parent refusal. Initial surviving evidence remains in `mutations.log` and `mutation-parent-count-before.log`; the corrected mutation failed behaviorally. No production guard was weakened to address a test failure.

## Limits and handoff

These cases use synthetic local Git objects and an injected authenticated-read boundary. They do not claim a real GitHub signature was locally cryptographically verified, a live API request was made, a check was published, or EKR was pushed. Production relies on authenticated GitHub's exact SHA and signature verification attestation. Coordinator-owned authenticated verification, CI, release, versioning and installation remain unexecuted in this unit. Seven pre-existing ignored privacy-scanner cases remain unchanged and outside this story.

Files outside the unit are confined to the assigned scratch logs, reports, Rust mutation harnesses and binaries, assigned Cargo target, and worktree-managed lease metadata. No AEP, normative document, lockfile, release file, workflow, policy or baseline was edited; no commit was created.

Owners: implementor — authored Rust source/tests and retained evidence; coordinator — independent review, integration, publication and managed-tree cleanup.
