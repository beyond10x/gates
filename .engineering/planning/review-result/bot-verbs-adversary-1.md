---
format: aep.planning-md/3
id: review-result:bot-verbs-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: bot merge, revert and delete-branch'
relations:
- reviews: story:bot-merge-revert
- reviews: story:bot-delete-branch
revision: 1
---
I found three breaks in `merge` and `revert`. A fourth, the hooks bypass you asked me to judge, is real but was already in the base. `delete-branch` held against everything I tried. My tests are committed on `review/bot-verbs-adversary`, head `963b303604273821ba8d108ff5ade1d3af2b9e45`. Author and committer are both `b10x-bot[bot]`. Not pushed, tree not finished, and my session lease is released.

```
unit: wave/bot-verbs (story:bot-merge-revert, story:bot-delete-branch), findings cover c1f0ef6
verdict: NEEDS-CHANGE
cases: executed 287→294, red 4
origin: introduced 2 / pre-existing 1 / undecided 0
wrote-outside-worktree: none
needs-coordinator: none
```

**1. Diff stat** (`git --no-pager diff --stat c1f0ef6..HEAD`): only the test file is touched.
```
 tests/adversary_bot_verbs.rs | 362 +++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 362 insertions(+)
```

**2. Cases added** in `tests/adversary_bot_verbs.rs`. Each red output below is from running that case alone.

- **`revert_reverts_only_its_one_revision_not_its_ancestry`: red.** It runs `revert --do-walk HEAD` and asserts that at most one commit is reverted.
  ```
  [main cefb810] Revert "base"
   3 files changed, 3 deletions(-)
  panicked at tests/adversary_bot_verbs.rs:97:5:
  `revert --do-walk HEAD` reverted more than HEAD (Ok(()))
  ```
- **`revert_takes_no_second_revision_from_a_ref_option`: red.** It runs `revert --tags HEAD` with tag `v1` on `main~1`.
  ```
  [main 352b377] Revert "two"
   2 files changed, 2 deletions(-)
  panicked at tests/adversary_bot_verbs.rs:117:5:
  `revert --tags HEAD` reverted the tagged commit too (Ok(()))
  ```
- **`merge_of_fetch_head_is_never_an_octopus`: red.** It runs `merge FETCH_HEAD` with two for-merge lines.
  ```
  [main e037566] Merge branches 'feature' and 'other' of example
  panicked at tests/adversary_bot_verbs.rs:143:5:
  `merge FETCH_HEAD` committed an octopus with 3 parents (Ok(()))
  ```
- **`commit_and_push_run_the_hooks_whatever_the_environment`: red.** The test re-runs itself three times: once with no injected variables (the control, which passes) and once each with `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT`.
  ```
  panicked at tests/adversary_bot_verbs.rs:198:9:
  "GIT_CONFIG_PARAMETERS: the refusing hooks [\"pre-commit\", \"pre-push\"] did not run: the bot commit or push succeeded",
  "GIT_CONFIG_COUNT: the refusing hooks [\"pre-commit\", \"pre-push\"] did not run: the bot commit or push succeeded",
  ```
- **`percent_escapes_in_a_branch_name_are_never_decoded_twice`: green.** My first fixture for this case contained `..`, so it failed on my own mistake rather than a defect. I fixed it to `x%2Fmain` and it now passes.
- **`ambiguous_github_answers_refuse_the_deletion`: green.**
- **`spellings_of_the_default_branch_are_refused`: green.**

**3. Suite run** (`B10X_GATES_GITLEAKS=… cargo test --locked --no-fail-fast`), after the cases existed. Exit 101. `adversary_bot_verbs`: 3 passed, 4 failed. Every other binary is green: 287 passed and 6 ignored, which is where the "before" count comes from. `bot_verbs` passed 16 and `bot_delete_branch` passed 12. The file passes `rustfmt --check` and clippy with `-D warnings`.

**4. Findings**

| # | Severity | Test | Defect | Verdict / origin |
|---|---|---|---|---|
| A | blocker | `revert_reverts_only_its_one_revision_not_its_ancestry`, `revert_takes_no_second_revision_from_a_ref_option` | `src/bot_args.rs:127` | NEEDS-CHANGE / introduced |
| B | warning | `merge_of_fetch_head_is_never_an_octopus` | `src/bot_args.rs:174` | NEEDS-CHANGE / introduced |
| C | warning | `commit_and_push_run_the_hooks_whatever_the_environment` | `src/delivery.rs:699` | CONFIRMED / pre-existing |
| D | note | none (design judgement) | `src/delivery.rs` `delete_remote_branch`, DELETE after the re-read | INFEASIBLE / introduced |

- **A. `revert` accepts options that choose more commits.**
  - **What it is:** `git revert` passes any option it does not know to its revision walker. The bot passes unknown long options straight through and only counts plain arguments as revisions. So `--do-walk`, `--all`, `--branches`, `--tags`, `--glob`, `--stdin` and `--not` all get past the one-revision check.
  - **Measured:** the result is one bot commit titled `Revert "base"` that reverts three commits. That breaks the contract's "no revert of a range", and the title misstates what the commit does.
  - **What reaches it:** any caller of `bot -- revert`.
  - **Fix:** for `revert`, admit only the long options it documents (`--mainline`, `--cleanup`, `--no-edit`, `--signoff`, `--gpg-sign`, `--no-gpg-sign`, `--rerere-autoupdate`, `--no-rerere-autoupdate`, `--reference`) and refuse every other long option. Also resolve the revision with `rev-parse --verify <rev>^{commit}` and pass that hash to Git.
- **B. `merge FETCH_HEAD` can merge several branches.**
  - **What it is:** `git merge FETCH_HEAD` merges every for-merge line in the fetch record.
  - **Measured:** a three-parent merge commit, which breaks "no octopus merge".
  - **What reaches it:** `bot -- fetch origin a b` writes two such lines, and the bot's own refusal for `pull` suggests "fetch, then merge".
  - **Fix:** resolve the revision to a single commit hash with `rev-parse --verify --end-of-options <rev>^{commit}` and merge that hash. This also fixes A. Optionally, refuse when `MERGE_HEAD` has more than one line before committing.
- **C. Your implementor's question: yes, the environment moves the hooks for `commit` and `push`.**
  - **Measured:** with `core.hooksPath` set through `GIT_CONFIG_PARAMETERS` or `GIT_CONFIG_COUNT`, a refusing `pre-commit` and a refusing `pre-push` hook both never ran. The bot's guard refuses `-c core.hooksPath=…` and `--config-env` by name, but admits the same setting from the environment.
  - **Why pre-existing:** I read the base with `git show 1a5ede1:src/delivery.rs` (lines 196–204). `Github::git` built the same `git` command without removing these variables. I did not run the test against the base.
  - **What reaches it:** the bot runs with the caller's environment. In production the pre-push scan would be skipped while the push still uses the App token.
  - **Limit on its weight:** this is not a new class. Setting `git config core.hooksPath` in the repository does the same, and the bot never checks which hooks are installed. Gates CI's "common / Security and privacy" check stays the backstop.
  - **Fix:** remove `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT` in `bot_command`, as `integration_command` already does. To also close the repository-config route in enrolled repositories, pass `-c core.hooksPath=<installed gates hook dir>` last on the bot's command line.
- **D. The gap between the last re-read and the DELETE (judgement, no failing case).**
  - **What it is:** GitHub's REST ref deletion has no expected-SHA condition. A push in the one-request gap gets its new tip deleted.
  - **Judgement:** acceptable as shipped. The pushed objects stay on the pusher's machine, and GitHub keeps unreachable objects for a while.
  - **A safer option exists:** a git-protocol delete that sends the expected old hash, such as `git push --force-with-lease=refs/heads/<b>:<tip> <url> :refs/heads/<b>`. The server compares and deletes atomically. The cost is routing a delete through the push path the bot otherwise refuses, so do it internally and never expose `--delete`. I believe GitHub's GraphQL `updateRefs` mutation with `beforeOid` does the same, but I have not verified that.
  - **Recommendation:** a follow-up story, not a blocker.

**Credential exposure.** `merge` and `revert` receive no token: `integrate` uses `bot_command(root, None)`. `Github::bot()` still mints a token for these verbs that is never used, which costs a network call but exposes nothing. `push` and `fetch` do inherit `HTTPS_PROXY`, `GIT_SSL_NO_VERIFY` and the repository's `http.*` settings, which in principle could hand the token to an intercepting proxy. That is old behaviour from before this wave, I did not test it, and an agent running as the same Unix user can read the App key file directly anyway.

**5. Attacks that held**
- Every forbidden long option, prefixes and `=` forms included, and every short cluster: no escape through a letter that takes a value.
- `--end-of-options` and `--` placement: Git fails closed.
- A value that swallows the next argument, such as `--into-name --abort` or `--mainline --abort`, cannot cancel the bot's trailing `--no-commit`.
- Merge drivers: refused from the repository config, the worktree config, mixed-case names and includes. Drivers injected through the environment are ignored.
- Filters: they still run during a merge, a risk the design already accepts.
- The bot commit uses the bot identity for both author and committer, and a refusing hook stops the merge commit.
- `delete-branch`:
  - It refuses tags, `refs/` names other than `refs/heads/`, `..`, `@{` and control characters.
  - Escaped names stay escaped: a `%` is sent as `%25`, so GitHub decodes once to the literal name.
  - It refuses a repository name with a dot segment or an extra `/`.
  - It refuses the default branch however it is spelled: `refs/heads/main`, `HEAD`, `@`.
  - It refuses when GitHub answers for a different branch name (a renamed branch).
  - It refuses when `protected` is missing or a string, when the merge base is missing, and when the comparison names a different base.

**6. Paths written outside the worktree:** none. The test fixtures are temporary directories that delete themselves; the shell and Rust temporary directory is `~/.cache/claude-tmp`, as configured.

```findings
- file: src/bot_args.rs
  line: 127
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: unknown long options pass to git revert's revision walker, so --do-walk, --tags, --all and similar revert more than the single admitted revision
- file: src/bot_args.rs
  line: 174
  category: acceptance
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: the single revision is not resolved to one commit, so merge FETCH_HEAD with two for-merge lines commits an octopus merge
- file: src/delivery.rs
  line: 699
  category: contract-drift
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: bot commit and push keep the caller's GIT_CONFIG_PARAMETERS and GIT_CONFIG_COUNT, so core.hooksPath set there skips pre-commit and pre-push although the guard refuses the same setting through -c
- file: src/delivery.rs
  category: concurrency
  severity: note
  verdict: INFEASIBLE
  origin: introduced
  message: the REST DELETE has no expected-SHA condition, so a push between the re-read and the delete is lost; a git-protocol delete with the expected old hash would be atomic
```
