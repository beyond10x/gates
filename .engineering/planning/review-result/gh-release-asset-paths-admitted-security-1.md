---
format: aep.planning-md/3
id: review-result:gh-release-asset-paths-admitted-security-1
kind: review-result
status: active
title: Security review 1 of the admission of release asset paths (2026-11-27)
relations:
- reviews: story:gh-release-asset-paths-admitted
revision: 1
---
## Security review 1 of the admission of release asset paths (2026-11-27)

Target: branch `feat/release-asset-paths` at f6f98ab6. Red tests: commit b0549b1 (taken into
the branch as 96b0f07). `api_protection_writes` with the cases: 126 passed, 2 failed.

Findings introduced by the change:

- `src/main.rs` (the asset read), boundary, warning: a FIFO named as an asset blocked the scan's
  read forever, and the read had no size bound. Test
  `release_asset_that_is_a_fifo_is_refused_without_blocking`. Fixed in 574d075: an asset that is
  not a regular file is refused before it is opened (symlinks followed, as `gh` follows them),
  and the read stops at the 128 MiB bound of `scan-artifact`.
- `src/main.rs` (the text asset scan), acceptance, warning: a text asset was scanned with the
  private rules only, so a credential in a text file under the home directory, refused before
  the change, would have been published. Test `release_text_asset_carrying_a_secret_is_refused`.
  Fixed in 574d075: text assets also go through the pinned gitleaks scanner ELF assets get.

Finding that predates the change (kept off the branch, filed as
`story:gh-published-file-spellings-scanned`): the content of a file `gh` publishes is scanned
only for the two-word spellings `--notes-file <f>` and `--body-file <f>`; `-F <f>`,
`--notes-file=<f>`, `--body-file=<f>`, `release new`, and `release -R <repo> create` publish it
unscanned. Identical at main 9f58450.

Checked against gh v2.102.0 without a finding: the option lists of `release create` and
`release upload` and the place of `-R`; short-flag clusters, `-t=` values, `--` as a value,
booleans with a default, unknown options refused; the `#` label split; the asset name is the
base name of the path; `#` in a directory name, a directory, a missing file, a backslash path
and `-t/home/...` refused; `release new` and `-R` before the verb fall back to the text scan.

Known limits: the file can change between the scan and the upload; the ELF scan reads printable
runs of 4 or more characters, so text broken by other bytes is not seen.

After the fixes: `cargo run --locked -- gate` exit 0, 810 passed, 0 failed, 21 ignored;
`api_protection_writes` 134 passed.
