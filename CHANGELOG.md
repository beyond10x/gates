# Changelog

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
