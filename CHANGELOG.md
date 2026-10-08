# Changelog

## 0.1.16 — unreleased

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
