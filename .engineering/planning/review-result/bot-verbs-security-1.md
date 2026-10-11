---
format: aep.planning-md/3
id: review-result:bot-verbs-security-1
kind: review-result
status: active
title: 'Security review 1: bot merge, revert and delete-branch'
relations:
- reviews: story:bot-merge-revert
- reviews: story:bot-delete-branch
revision: 1
---
```
unit: wave/bot-verbs of gates (story:bot-merge-revert, story:bot-delete-branch, design:bot-verbs), tree c1f0ef6; findings committed at review/bot-verbs-security 9c3345b
verdict: NEEDS-CHANGE
cases: executed 287→291, red 4
origin: introduced 3 / pre-existing 1 / undecided 0
wrote-outside-worktree: 2 paths
needs-coordinator: whether a revert that runs a repository merge driver blocks the wave (owner decision vs. the design's "no new class" argument); ruleset-protected branches in delete-branch
```

**Verdict:** NEEDS-CHANGE. Four new test cases fail. The two blockers are on `revert`. Delete-branch passed every check I could run without a token. Branch head: `review/bot-verbs-security` at `9c3345bc0ced7f169c4e00fe57cf7516d0a38955`. Author and committer are both `b10x-bot[bot]`. It is not pushed and the tree is not finished.

**1. Diff stat** (`git --no-pager diff --stat c1f0ef6..HEAD`)
```
 tests/security_bot_verbs.rs | 240 ++++++++++++++++++++++++++++++++++++++++++++
 1 file changed, 240 insertions(+)
```
Only a test file changed. Nothing under `src/` was touched.

**2. Cases added** in `~/.local/state/worktree/trees/b10x/gates/gates-security-bot-verbs/tests/security_bot_verbs.rs`. All four are red now. This is the output of the file run alone (`B10X_GATES_GITLEAKS=… cargo test --locked --test security_bot_verbs`), before the full suite ran:
```
---- merge_refusal_names_no_local_path stdout ----
the refusal carries the local path ~/.cache/claude-tmp/.tmps2ol9l: bot merge refused: ~/.cache/claude-tmp/.tmps2ol9l/.git/config includes other configuration, which may name a merge driver; remove the include to merge as the bot
---- revert_commits_only_the_reversion stdout ----
assertion `left == right` failed: the bot's Revert commit carries changes it did not revert
  left: "target.txt\nunrelated.txt"
 right: "target.txt"
---- commit_and_push_ignore_configuration_from_the_environment stdout ----
the bot commit skipped the repository's pre-commit hook: configuration from the environment moved core.hooksPath
---- revert_refuses_a_configured_merge_driver stdout ----
the configured merge driver ran during a bot revert: the revert is still in progress: … nothing staged … bot Git commit failed (exit status 1)
test result: FAILED. 0 passed; 4 failed
```
(The real path printed was the absolute home path; I have written it here as `~/`.)

I then changed the environment case so it reports both hooks at once, and re-ran it alone: `the bot skipped the repository's ["pre-commit", "pre-push"] hook(s): configuration from the environment moved core.hooksPath`.

**3. Full suite:** `B10X_GATES_GITLEAKS=… cargo test --locked --no-fail-fast` exited 101.
- Every other target is green: bot_delete_branch 12, bot_routes 10, bot_verbs 16, published_merge 121, security 71, and the rest.
- The only failure is `--test security_bot_verbs` (4 failed).
- 287 passed; my 4 cases are the only red ones. 287 is also the count with my file left out.
- `cargo fmt --all --check` and `cargo clippy --test security_bot_verbs -- -D warnings` are clean.

**4. Findings**

| # | Severity | Failing test | file:line | Verdict / origin | Fix |
|---|---|---|---|---|---|
| 1 | blocker | `revert_refuses_a_configured_merge_driver` | src/delivery.rs:800 | NEEDS-CHANGE / introduced | Run `merge_drivers` for `Verb::Revert` too, and add the `merge-driver-configured` outcome to `gates.delivery.Revert` in ess/domains/delivery.yaml |
| 2 | blocker | `revert_commits_only_the_reversion` | src/delivery.rs:903 | NEEDS-CHANGE / introduced | In `preflight`, refuse a revert when the index differs from HEAD (`git diff --cached --quiet`) |
| 3 | warning | `commit_and_push_ignore_configuration_from_the_environment` | src/delivery.rs:726 | CONFIRMED / pre-existing | Move the env removal from `integration_command` (:763) into `bot_command`, or better an allowlisted `env_clear` that also drops GIT_DIR, GIT_WORK_TREE, GIT_EXEC_PATH and GIT_INDEX_FILE |
| 4 | note | `merge_refusal_names_no_local_path` | src/delivery.rs:857, :864 | CONFIRMED / introduced | Name `.git/config` or `config.worktree` relative to the Git directory, not `file.display()` |

1. **A revert runs the merge driver the repository configures.** The owner decision adds merge and revert "with the refusals listed above (…, and a merge driver named in `.git/config`)", and the design gives revert "the same refusals as `merge`". `preflight` checks drivers only for merge, and the ESS `Revert` command dropped that outcome. So the unit's own specification and code agree with each other, but neither matches the decision.
   - **What reaches it:** any `bot -- revert` in a repository that has a `merge.<d>.driver` key and a `.gitattributes` `merge=<d>` line, on a path changed on both sides.
   - **Note:** the design itself argued merge drivers are "no new class" because `commit` can already run filters. The coordinator may grade this on the decision rather than on its security impact.
2. **A revert commits whatever was already staged.** `git revert --no-commit` reverts against the current index, so changes staged earlier ride inside the bot's `Revert "…"` commit. `merge` refuses a dirty index (I checked this by hand). This breaks the acceptance outcome "one commit reverting the target". The content is still scanned by pre-commit, so the harm is to provenance, not secrets.
   - **What reaches it:** `git add` of anything, then `bot -- revert`.
3. **The implementor's finding holds.** `commit`, `push` and `fetch` still pass the caller's `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT` to Git. Those set `core.hooksPath`, so pre-commit and pre-push are skipped, which is exactly what the `-c` argv refusal exists to stop. The base `Github::git` did the same, so this predates the wave.
   - **Why only a warning:** the caller can already do the same through `git config --local core.hooksPath`. They can also read the App key, which is protected only by mode 600 and owned by the same user. The CI `common / Security and privacy` check remains the scan nobody can skip. This is a guard that is inconsistent, not a privilege boundary.
4. **A refusal prints a local path.** The include refusal and the "cannot be read" refusal print the absolute path to `.git/config`, which contains the home directory. That works against "refusals carry no private data" and the `personal-paths` rule wherever the text gets pasted.

Two judgement points I could not turn into a test:
- **Ruleset-protected branches (warning, undecided):** delete-branch decides "protected" from the `protected` field of `GET /branches/<b>` (src/delivery.rs, `delete_remote_branch`). I could not confirm that this field covers ruleset-only protection. The App is the bypass actor of `b10x-bot-branch-authority`, so its DELETE would not be stopped by the ruleset. Proposed fix: also read `GET /repos/<r>/rules/branches/<b>` and refuse when any `deletion` rule applies. Settling it needs the live API, which I did not call.
- **Unneeded token for merge/revert (note):** `main.rs:242` mints an App token even though neither verb uses it (`bot_git` never passes it). It runs after the argument and preflight checks, so the owner's rule holds; it is just a token that need not exist.

**5. Reviewed and found nothing wrong**
- **Identity:** merge and revert commit through `run_bot` with the bot's author and committer environment, and the hooks run. The existing tests cover this, and my cases confirm it.
- **Forbidden options:** every long option is matched by every prefix, including `--` with an empty name and `--no-` prefixes. The bot's `--no-ff --no-commit` come after the caller's options. Exactly one revision is accepted, with no range forms.
- **Merge driver check:** it reads the config files as data with `--no-includes`, refuses `include` and `includeIf` (key names are lowercase, and the regex still matches), and drops the caller's config environment for merge and revert.
- **Operation in progress:** MERGE_HEAD, REVERT_HEAD, CHERRY_PICK_HEAD, rebase-merge, rebase-apply and sequencer are all read from the per-worktree Git directory.
- **delete-branch arguments:** `--repository` is required and shape-checked; exactly one name, no options. Names are checked to `check-ref-format` rules, and only `refs/heads/` is ever addressed, so a tag cannot be deleted. Every path segment is percent-encoded.
- **delete-branch remote checks:** it refuses the default branch, a protected branch and a renamed branch. It requires the comparison status to be `ahead` or `identical` and the merge base to equal the tip. It re-reads the tip before the DELETE, and the remaining race is the one-request window the story already names. The DELETE goes through the REST API as the App, and the credential is minted only after `check` and `delete_branch`.
- **No remote history rewrite:** no new verb can force-push or delete a tag; `push --delete`, `-d`, `:ref`, `--prune` and `--mirror` stay refused.
- **Refusals and private data:** API errors show the status only, through `ApiFailure`. Finding 4 is the one exception.
- **GIT_DIR and GIT_WORK_TREE:** `preflight` and `integrate` see the same environment, so the driver and in-progress checks follow whatever GIT_DIR names. This is the same trust level as `--repo`, and finding 3 covers it as defence in depth.

**6. Paths written outside the worktree**
- `~/.cache/claude-tmp/secrev-suite.log`: the full suite log, kept.
- `~/.cache/claude-tmp/secrev-probe.fubX/`: a manual probe of merge and revert with a staged change, now deleted.

Test temporary directories were created and removed by `tempfile`. I also took and released my own worktree lease, `secrev-bot-verbs-20261012`.

**7. Findings block**
```findings
- file: src/delivery.rs
  line: 800
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: bot revert runs a merge driver named in .git/config although the owner decision requires the merge-driver refusal for revert as for merge (revert_refuses_a_configured_merge_driver)
- file: src/delivery.rs
  line: 903
  category: acceptance
  severity: blocker
  verdict: NEEDS-CHANGE
  origin: introduced
  message: git revert --no-commit folds a previously staged change into the bot's Revert commit, so the commit is not one reversion of the target (revert_commits_only_the_reversion)
- file: src/delivery.rs
  line: 726
  category: integrity
  severity: warning
  verdict: CONFIRMED
  origin: pre-existing
  message: commit, push and fetch inherit GIT_CONFIG_PARAMETERS/GIT_CONFIG_COUNT, which move core.hooksPath and skip pre-commit and pre-push despite the -c refusal (commit_and_push_ignore_configuration_from_the_environment)
- file: src/delivery.rs
  line: 864
  category: integrity
  severity: note
  verdict: CONFIRMED
  origin: introduced
  message: merge-driver include and parse refusals print the absolute local configuration path, which carries the home directory (merge_refusal_names_no_local_path)
- file: src/delivery.rs
  category: judgement
  severity: warning
  verdict: INFEASIBLE
  origin: undecided
  message: delete-branch reads protection only from the branches API protected field, so a ruleset-only deletion rule the App bypasses may not be refused; not testable without the live API
```
