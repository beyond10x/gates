# Changelog

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
