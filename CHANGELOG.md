# Changelog

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
