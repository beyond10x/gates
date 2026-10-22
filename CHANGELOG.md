# Changelog

## 0.1.23 — 2026-10-22

- A GET that GitHub answers with a 5xx status is sent again, at most 5 times in all, waiting
  0.5, 1, 2 and 4 seconds; any other answer returns at once and writes are never sent again. On
  2026-10-22 `commits/<sha>/pulls` answered 500 for 10 of 23 merges of one repository, to the App
  and to a personal token alike, and every such answer refused the bot push.
- A historical merge whose `commits/<sha>/pulls` still answers 5xx is proved through the pull
  request its subject names (`Merge pull request #<n> from …`, or `… (#<n>)` for a squash): that
  record must name the commit as its merge commit and then passes every check a listed one does.
  A subject naming no pull request, a 4xx on the list, and a record naming another commit refuse.
- A refused published-merge read names its method and path, as `GET <path>: <status>`.

## 0.1.22 — 2026-10-20

- `api` and `gh -- api` refuse a write to a ruleset or to branch protection before the policy is
  read and before a token is minted, naming the path and saying "ruleset and branch protection
  changes are the owner's". On 2026-10-20 a ruleset of another repository was changed through
  `api` with the bot token. `api` refuses any method but GET and HEAD on the repository and
  organization ruleset paths and the branch protection paths (and what is below them, and under
  the `/repositories/<id>/` and `/organizations/<id>/` aliases), judged in every percent-decoded
  (first decoding strict, at most 8), lowercased, dot-resolved reading with repeated or trailing
  `/` and the query dropped; a write whose path cannot be decoded; and a `/graphql` request whose
  body or query string names one of the six ruleset or branch protection mutations as a whole
  GraphQL name. `gh -- api` refuses any argument or named file (`--input`,
  `-F`/`--field <key>=@<file>`, read as UTF-8, UTF-16 or UTF-32) carrying such a path or
  mutation, whatever the method, or still changing after 8 percent-decodings; standard input; a
  `{owner}`/`{repo}` placeholder some owner or name would turn into such a path, `{branch}`
  outside a whole field value, any placeholder in the GraphQL `query` field, and an argument
  whose placeholders would take more than 4 MiB of fillings to judge; and an argument holding a
  `Content-Encoding:` or `Transfer-Encoding:` header text. Paths are judged in time linear in
  the text. A refusal shows a path found in a file only up to its `rulesets` or `protection`
  segment. Reads go through
  `api --method GET` (`gates.delivery.BotApi`). The App's `administration` permission is
  unchanged: the App key still reaches the API without `b10x-gates`.

## 0.1.21 — 2026-10-14

- `ci` reads the private policy from `B10X_GATES_POLICY_GZ` (the policy compressed with
  `gzip -9` and encoded as base64) when it is set and non-empty, else from
  `B10X_GATES_POLICY_JSON` as before, else from the protected file. GitHub refuses a secret over
  48 KB, which the policy outgrew. A set but undecodable value is refused naming the variable,
  never a fallback; the decompressed policy is bounded at 4 MiB
  (`gates.delivery.LoadCiPolicy`).
- `common.yml` declares the optional secret `B10X_GATES_POLICY_GZ` and passes it to `ci`;
  `B10X_GATES_POLICY` is now optional and still passed as `B10X_GATES_POLICY_JSON`, so callers
  on an older pin keep working and move to the new secret when they bump their pin.
- `policy publish` writes the CI secrets from `origin/main:policy.json` of the policy repository,
  never a working-tree file: a dry run by default (commit, targets, sizes), `--apply` writes with
  `gh secret set` and reads back with `gh secret list`; targets come from a JSON file; any value
  of 48,000 bytes or more publishes nothing; a marker in the state directory makes a repeat
  print `unchanged` (`--force` publishes anyway) (`gates.delivery.PublishPolicy`).

## 0.1.20 — 2026-10-13

- The release executable is built for `x86_64-unknown-linux-musl` again. The 0.1.19 asset was
  a static glibc build: it resolves names by loading the host's `libnss_*` modules, and its
  second GitHub request faulted (exit 139, nothing printed), so `bot -- delete-branch` and
  `api` crashed while `commit` and `push` worked. The source is unchanged; 0.1.19 users should
  move to 0.1.20 or keep 0.1.18.
- `scan-artifact` refuses a statically linked executable (no `PT_INTERP`) that carries glibc's
  name service switch (`nsswitch.conf`), before any scanner runs, naming the musl target
  (`gates.delivery.ValidateArtifact`, `static-name-service`).

## 0.1.19 — 2026-10-13

- `bot -- delete-branch` reads the comparison of the branch tip with the default branch again.
  0.1.18 built `compare/<tip>...<default>`, which the API client's `..` path guard refuses, so
  every merged branch was refused with "invalid GitHub API path". The separator is now sent
  percent-encoded; the guard is unchanged, and the delete-branch test doubles apply it.
- A comparison GitHub cannot answer is refused and nothing is deleted
  (`comparison-unreadable`).
- `install` without `--repository` or `--policy` reinstalls from the installed hooks'
  `config.json`: repository, policy, key and scanner, each only when no flag or `B10X_GATES_*`
  names it. The file is read through the owner-only checks, and only for the repository it
  names; a `--repository` naming another one is refused with both names. With both
  `--repository` and `--policy` named, the file is not read, so a left-behind or damaged
  configuration never blocks an explicit repair install.

## 0.1.18 — 2026-10-13

- `bot -- delete-branch <branch>` runs without `--repository`: the repository comes from the
  installed hooks' protected `config.json`, as for the other bot verbs. An explicit
  `--repository` still wins; with neither, the refusal names both routes. A repository Git
  refuses for another reason (shallow history, an unknown format) is refused with its cause,
  not reported as uninstalled.
- `delete-branch` judges classic protection by the branch's `protection.enabled`. GitHub's
  `protected` is true for every branch under a ruleset, so 0.1.17 refused every branch of a
  repository carrying the bot-authority ruleset. A missing or non-boolean `protection.enabled`
  is refused.
- Rulesets are judged by where each rule comes from: every rule must name its ruleset, the
  restricting rules (`creation`, `update`, `deletion`, `non_fast_forward`) must all come from
  one ruleset and each appear once, and any other rule type beyond the commit and branch name
  patterns is refused. A second ruleset that restricts the branch is refused even when its rule
  types match the bot-authority ruleset's.
- Tests prove that pre-push and `check` admit a branch and an annotated tag cut from a pull
  request the bot merged through the API, one merge past the baseline, on public and private
  repositories; no baseline move is needed. A merge whose second parent is not the bound pull
  request head, or that no merged pull request records, is refused.
- `ess/`: `gates.delivery.DeleteBranch` resolves its repository from the flag or the installed
  configuration and gains the ruleset attribution outcomes.
- No policy field or receipt format changes. The version increment invalidates receipts retained
  under 0.1.17, so the first check after upgrading scans in full once.

## 0.1.17 — 2026-10-11

- `bot -- merge <revision>` and `bot -- revert <revision>` run as the bot. Each takes exactly one
  revision, resolved to one commit before Git runs, so a range, a second revision or a
  `FETCH_HEAD` with several branches is refused. Git runs the `--no-commit` form, and the bot then
  commits the result, so `pre-commit` and `commit-msg` run and the author and committer are the
  bot. Long options are admitted by exact name from a list per verb; every other option is
  refused, among them `-s`/`--strategy`, `-X`, `--squash`, `--ff-only`,
  `--allow-unrelated-histories`, `--edit`, `-n` and the sequencer verbs. A merge driver or an
  include in the repository's own configuration, an operation already in progress, a revert over
  staged changes and a merge with more than one `MERGE_HEAD` are refused. Neither verb mints a
  token. A conflict leaves the index and prints the finish and abort routes.
- `bot --repository <owner>/<repo> -- delete-branch <branch>` deletes a remote branch through the
  REST API as the App, only when it is not the default branch, not protected, carries no ruleset
  rule beyond the organization's bot-authority and identity rules, and its tip is an ancestor of
  the default branch and has not moved since it was read. Only `refs/heads/` is addressed, so a
  tag is never deleted. The `push --delete` refusal names this verb; the API route stays the only
  one for an unmerged branch. GitHub's ref deletion takes no expected tip, so a push landing in
  the one request between the last read and the deletion is deleted with the branch.
- `rebase`, `cherry-pick`, `pull` and `am` stay refused and name the merge verb as the route.
- Every bot Git command drops `GIT_CONFIG_PARAMETERS` and `GIT_CONFIG_COUNT` from its
  environment. Before this release a caller could set `core.hooksPath` there and skip
  `pre-commit` and `pre-push`, which the `-c` refusal exists to stop.
- `ess/` moves to format `ess/24` and gains the `gates.delivery` domain: `Merge`, `Revert`,
  `RemoteBranch` and `DeleteBranch`, with every refusal as an outcome.
- No policy field or receipt format changes. The version increment invalidates receipts retained
  under 0.1.16, so the first check after upgrading scans in full once.

## 0.1.16 — 2026-10-08

- Delivery refusals name their cause. A protected file's refusal names its path and what is
  wrong: missing, not a regular file, a symlink, its mode and the mode it needs with the `chmod`
  that fixes it, its owner, or a parent or output directory writable by others. A failed bot Git
  verb names itself and Git's exit status, and a commit with an index equal to `HEAD` and no
  other source of changes says "nothing staged". An unsupported `gh` command names itself and the
  supported list; a failed `gh` child names its exit status.
- `api` carries GitHub's message for a 4xx answer: the status, `message` and each `errors` entry,
  after the private-rule and personal-path matchers have read both the raw and the shown text.
  On a match, or without a trusted policy, the message is withheld and the status still printed.
  Control characters are removed and each message is cut to 300 bytes. A 5xx or non-JSON answer,
  and every caller without a policy, stays status only.
- `api` checks its output directory before the request, and reports a remote write that
  succeeded as success (exit 0), with its status, number and vetted URL, when the response file
  cannot be written or the answer carries no JSON body. A retry is what made a created pull
  request answer 422.
- `bot` checks its arguments before it mints a token and prints the supported route:
  `merge`, `pull`, `rebase`, `cherry-pick` and `am` name `git merge --no-ff --no-commit <branch>`
  followed by `b10x-gates bot -- commit -F -`; a `push` that deletes a remote ref (`--delete`,
  `-d`, `--prune`, `--mirror`, any prefix Git accepts for them, `:<branch>` and `+:<branch>`)
  names `b10x-gates api --method DELETE --path /repos/<owner>/<repo>/git/refs/heads/<branch>`.
  No verb is added; `.engineering/planning/design/bot-verbs.md` proposes which could be.
- The bot's hook and configuration guard closes three bypasses that predate this release: an
  abbreviated `--no-verify` (`--no-verif`), `-n` inside a commit short cluster (`-nm`), and
  `--receive-pack`, `--upload-pack` and every prefix Git accepts for `--exec` (`--e=`), which ran
  a caller-chosen command with the bot token in its environment. `Github::git` and the argument
  check now share one guard.
- No policy field or receipt format changes. The version increment invalidates receipts retained
  under 0.1.15, so the first check after upgrading scans in full once.

## 0.1.15 — 2026-10-07

- `personal-paths` decodes hex-encoded path components. A JSON `"components"` array of hex
  strings, the form ESS writes for the absolute output directory in
  `.ess-output/state.json` (`"encoding": "UnixBytes1"`), is decoded component by component,
  joined as an absolute path and held to the same home-path rule as text, so an encoded Linux or
  macOS home directory is refused like the plain one. Until now `686f6d65` passed as hex while
  `home` was refused. Compact and pretty-printed JSON are both read; the finding is reported on
  the line the `"components"` key opens, and its content digest covers every line the array
  spans. The marker is not required, and a relative array such as a ledger entry is not a home
  path. The delivery verbs refuse the same arrays. The encoding does not say whether an array
  is absolute, so a relative array whose first segment is `home` or `Users` is refused too.
- The privacy line passes stay linear in the number of findings per unit. The soft-wrap pass
  recounted line breaks from the start of the unit for every match and looked each finding up
  in a growing list (60x the time for 8x the input); it now carries the count forward and uses
  sets. Findings, their lines and their order are unchanged.
- A repository whose commits after its adoption baseline carry such a record is refused on its
  next full scan once it adopts this version, because every commit since the baseline is
  scanned: move its baseline past the commit that stopped tracking the record first.
- Admit an earlier GitHub update-branch commit of a pull request updated more than once. The
  update must lie on the first-parent line of the merged head, every commit between them must be
  a direct bot commit or a GitHub update of the same pull request, its own tree must be the clean
  local merge of its parents, and the pull request's merge passes the terminal-merge proof.
  Until now only the final update could bind, so a pull request updated twice refused every
  later bot push with "updated pull request summary does not bind this accepted head".
- Gates has no public website documentation any more: `b10x.docs.yaml`, the documentation
  bundle, check and Pages façade workflows, and the README and AGENTS documentation blocks are
  removed. The README is the documentation; `docs/adoption.md` stays as a repository document.
- No policy field or receipt format changes. The version increment invalidates receipts
  retained under 0.1.14, so the first check after upgrading scans in full once.

## 0.1.14 — 2026-10-05

- Admit a GitHub-created two-parent merge whose pull-request head was cut before the base moved
  on. 0.1.13 admitted a merge only when it adopted the head's tree unchanged, so every pull
  request merged after another one had landed refused later bot pushes with "pull request head
  did not incorporate its merge basis" (beyond10x/atlas PR #65, merged onto PR #64).
- The merge's tree must now equal Git's own merge of its two parents, recomputed locally with
  `git merge-tree --write-tree`. The merge refuses when that local merge conflicts, even if the
  recorded tree is the conflicted one, and when the recorded tree differs from it, so a merge
  carrying any change of its own is refused. A head that already contains its base still merges
  to the head's tree, so every merge 0.1.13 admitted is still admitted.
- The local merge reads no attributes from the worktree (`--attr-source` is the empty tree), so
  a checked-out `.gitattributes` cannot select a merge driver that resolves a conflict. It also
  refuses a non-empty `$GIT_DIR/info/attributes`, which `--attr-source` does not replace, and a
  repository-configured `merge.default` or `merge.<name>.driver`, either of which could resolve
  a conflict and report the merge clean. Rename detection, directory renames and
  renormalization are pinned to Git's defaults (`merge.directoryRenames=conflict`,
  `merge.renormalize=false`, `merge.renames=true`, `diff.renames=true`), so repository config
  cannot turn a conflicting merge clean either.
- A GitHub update-branch commit is now held to the same proof: Git's merge of its two parents
  (prior head, base) must be clean and equal its recorded tree. Before, its tree was bound only to
  the final merge's tree, so an update commit carrying a change of its own was admitted.
- The local merge needs Git 2.43.0 or later (`merge-tree --write-tree` since 2.38.0,
  `--attr-source` since 2.41.0, and the `merge-tree` crash under `--attr-source` fixed in 2.43.0).
- The proof applies to public and private repositories alike. Everything else is unchanged:
  public repositories still require the exact App-only branch authority with no private
  fallback, private repositories still require the exact bot account to open and merge the pull
  request, refuse squash merges and walk every head commit for the exact bot identity, and
  contradictory or other visibilities refuse.
- No policy field or receipt format changes. The version increment invalidates receipts
  retained under 0.1.13, so the first check after upgrading scans in full once.

## 0.1.13 — 2026-10-04

- Admit a GitHub-created merge in the delivery range of a private enrolled repository. Until
  now `published_merge::verify` refused every private repository ("remote repository is not
  public"), because the App-only branch ruleset it reads is unavailable on that plan, so each
  pull-request merge blocked later bot pushes until the policy baseline was moved past it.
- The authenticated repository visibility selects the proof. Public repositories still require
  the exact App-only branch authority; a public repository without it refuses, and the private
  proof is never a fallback. Contradictory or other visibilities (`internal`) refuse.
- On a private repository each merge must be the verified GitHub-signed two-parent merge of a
  completed same-repository pull request whose `merge_commit_sha` is that merge, whose head is
  the second parent and supplies the tree unchanged, and which was both opened and merged by the
  exact bot account: login, `Bot` type and numeric id. Every head commit is still walked and
  must carry the exact bot identity. Update-branch merges follow the same rule.
- Squash merges are refused on private repositories. Their head commits are outside the walked
  ancestry, and without a ruleset nothing proves who wrote them.
- No policy field or receipt format changes. The version increment invalidates receipts
  retained under 0.1.12, so the first check after upgrading scans in full once.

## 0.1.12 — 2026-10-03

- Add `scan-artifact` for bounded ELF64 little-endian release executables. It validates the
  complete section and segment inventory, scans embedded printable data with the existing private
  policy, invokes pinned Gitleaks over the nonempty extraction, and reports the complete input
  SHA-256 without executing the artifact. Malformed, truncated, compressed and unsupported inputs
  fail closed.
- Verify an already-published GitHub update-branch commit when it is the exact head of a
  completed same-repository pull request merged by the organization bot. Both the update and
  final merge must have authenticated identities, signatures, parents and trees. The final
  merge must retain the update's tree and merge onto the update's second parent.
- Keep complete ancestry verification, exact direct-bot identity, App-only branch authority,
  scanner checks and receipt verification unchanged. Unsupported intermediate update graphs,
  missing evidence and ambiguous pull-request associations continue to refuse publication.
- No policy field or receipt format changes. The version increment invalidates receipts
  retained under 0.1.11, so the first check after upgrading scans in full once.

## 0.1.11 — 2026-09-29

- `check` and the pre-push hook scan only the commits no verified retained receipt covers. A
  retained receipt for an ancestor of the candidate head is reused only when it verifies in full
  against the candidate Gates builds for that ancestor from local Git objects: trusted signer,
  repository, baseline, exact commit range and objects, policy digest, Gates and scanner version.
  Of those, the one covering the most commits is chosen; every other commit, merged side
  branches included, and every tag is scanned, each commit against its own parent as before. Any
  receipt that does not verify leaves the scan whole.
- `check` also considers the receipts the pre-push hook retained in the Git common directory's
  `b10x-gates-hooks`, and writes a reused exact-head receipt to `--receipt`.
- Object sizes and blob bytes are read through one `git cat-file --batch-command` per candidate
  instead of two `git` processes per blob, with the same size limits and refusals; an object
  missing from the local store still refuses and names the fetch that supplies it.
- The receipt format and its statement do not change: it states that the common checks passed
  for every commit from the baseline to its head, and a receipt signed after a partial scan is
  byte-identical to one signed after a full scan. `verify` and `ci` are unchanged.
- Change no policy field or receipt format; the version increment alone invalidates receipts
  retained under 0.1.10, so the first check after upgrading scans in full once.

## 0.1.10 — 2026-09-25

- A refused Git operation now names its subcommand and exit status, and an object the local store
  lacks is named by id with the remedy, `git fetch origin`. Before this every such refusal read only
  "Git object operation failed" — including `publish` against a remote default branch that had
  advanced past the last fetch, whose cause was not findable from the message.
- Git's stderr and the operation's arguments are still never echoed: both can carry candidate
  bytes. The subcommand and object ids are the only things named.
- Change no policy field or receipt format; the version increment alone invalidates receipts
  retained under 0.1.9.

## 0.1.9 — 2026-09-25

- A missing or unreadable trusted policy or signing key now names the input, its path, and the
  flag or variable that supplies it (`--policy` / `B10X_GATES_POLICY`, `--key` /
  `B10X_GATES_KEY`). Before this every subcommand, `verify` included, refused with only
  "protected file unavailable", which agents repeatedly routed around instead of closing.
- Change no policy field or receipt format; the version increment alone invalidates receipts
  retained under 0.1.8.

## 0.1.8 — 2026-09-25

- Admit a `merge_group` (`checks_requested`) event in `ci`, so the shared check can gate a GitHub
  merge queue. Before this every merge-group run refused with "push commit missing". The queue's
  merge commit, `merge_group.head_sha`, must be an exact commit id and is fetched by that id; it is
  bound exactly as a push of that commit to the protected branch would be — scanned from the policy
  baseline, with the same receipt lookup. `base_sha` decides nothing, as `before` does not for a
  push. A missing head refuses and never falls back to the payload's push fields; repository
  identity and a fresh object directory are still required.
- A caller adds `merge_group:` to its workflow's `on:`; `common.yml` itself reads no event-specific
  field.
- Change no policy field or receipt format; the version increment alone invalidates receipts
  retained under 0.1.7.

## 0.1.7 — 2026-09-22

- Admit a two-parent GitHub App merge whose head does not contain its base when the base's tree
  equals the fork point's: the merge adopts the head's tree, so a base that added nothing since the
  fork cannot have been dropped. A base that did add content is still refused. Without this a
  repository whose default branch took one such merge could never deliver again
  (epistemic-knowledge-runtime PR #12).
- Admit a one-parent GitHub App commit (a squash merge) on shape; it is still proved against the
  remote — verified signature, exact bot author, `merged_by`, `merge_commit_sha`, and the single
  parent equal to the pull request base.
- Raise the per-blob scan limit from 64 to 128 MiB and the total from 256 to 512 MiB.
- Change no policy field or receipt format; the version increment alone invalidates receipts
  retained under 0.1.6.

## 0.1.6 — 2026-09-22

- Verify already-published GitHub App merge ancestors through authenticated repository, branch authority, commit and pull request evidence in both publication and pre-push. A legitimate bot merge with GitHub as committer no longer prevents subsequent bot delivery. New direct commits retain exact bot author and committer checks; ambiguous or missing historical proof refuses.
- Share the ancestry verifier across delivery entry points and validate every commit in the complete candidate DAG. Keep policy, adoption baselines, common scanners, signed receipts and commit-time identity checks unchanged.
- Change no receipt format; the version increment invalidates receipts retained under earlier binaries.

## 0.1.5 — 2026-09-16

- Admit `dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>` as a commit **author**. A dependency update was refused with `inadmissible authorship` and could not merge anywhere in the organization. Nothing else relaxes: the commit is scanned like any other, every other identity is still refused, and local delivery still requires the organization bot as author *and* committer, so this admits a pull request and never a push.
- Resolve a body file named by `--body-file`, `--notes-file` or `--input` against `--repo`, which is the directory `gh` itself resolves against. A relative path was unreadable here and perfectly readable to the child.
- Change no policy field or receipt format; the version increment alone invalidates receipts retained under 0.1.4.

## 0.1.4 — 2026-09-16

- Supply the workflow token to the candidate object fetch, so the shared gate works on a private repository. It served objects anonymously before, which only a public repository does; a private adopter refused with "candidate object fetch failed". The credential goes through `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_0`/`GIT_CONFIG_VALUE_0`, never argv or a URL, because argv is readable by every process on the runner.
- Change no check, policy field or receipt format; the version increment alone invalidates receipts retained under 0.1.3.

## 0.1.3 — 2026-09-16

- Add `forbidden_patterns` and `allow_patterns` to the policy, at wire version 2. An allowance admits only what its `(?P<admit>...)` group captures and never reaches `personal-paths`; a rule that matches an ordinary line or the empty one is refused at load. A version 2 policy is unreadable by 0.1.2, which refuses it and fails closed.
- Treat a change as answerable for the lines it introduces, not for the file it lands in: a finding whose exact line is already present in that path's previous version is inherited. Without it, editing one line of a document refused the commit for every finding already in it — 64% of all refusals measured over 757 commits of real work.
- Open the personal-path boundary on a backtick, a table pipe, an emphasis marker, a diff minus and an invalid byte; match `/Users/` case-sensitively and require the first segment to end the reference or be followed by a slash, so a REST route is not a home directory. Cover UNC profile paths, strip Unicode format characters, and catch a literal a soft wrap split over two lines.
- Leave a unit with a NUL byte in its first 8 KiB to the secret scanner.
- Scan published content before it is sent: `gh`, `api --input`, and the new `scan-text`. An option naming a body file is scanned by its contents.
- Allow an exception to cover a tree with a trailing `*`, any line with line 0, and any content with an empty digest; add `policy except --findings` with `--any-line` and `--any-content`.
- Hardlink the thirteen hook names to one binary per repository, 7 MiB instead of 89 MiB, and record the installing version. Narrow the policy file to owner-only during `install`.
- Replace span containment with a merged disjoint cover and a binary search; a 4 MiB single line went from 31 s to under 2 s.

## 0.1.2 — 2026-09-10

- Publish the release that the shared workflow on `main` downloads, so a repository pinning a current Gates commit fetches a verified binary for that exact source.
- Change no check, policy field or receipt format; the version increment alone invalidates receipts retained under 0.1.1.

## 0.1.1 — 2026-09-10

- Require the exact organization bot or GitHub Actions raw commit author on every commit after the trusted adoption baseline, before scanning or receipt reuse, including intermediate commits and merged side branches.
- Require the exact organization bot author and committer when a commit is created locally.
- Add the `commit-authorship` result and invalidate receipts retained under 0.1.0.

## 0.1.0 — 2026-09-10

- Add common secret/privacy checks over Git objects, coordinated local hooks, exact adoption baselines and protected exceptions.
- Sign and verify complete Ed25519 receipts; reuse valid evidence without scanner execution and retain it across bot publication retries.
- Provide bot delivery and a reusable workflow that treats fork candidates only as data, independently of Atlas.
