# AGENTS.md — gates

## Serves

- **O2 — decisions as data, with evidence.** Signed receipts bind complete common checks to exact Git objects and policy.
- **O6 — self-improvement, built into all of it.** Valid retained evidence avoids repeated scanners without weakening enforcement.

## Contract

Anything executable is Rust, with clap for CLI arguments. Use a managed worktree for repository changes and AEP for planning-store mutations.

Gates owns common security/privacy checks, receipt verification, coordinated local hooks and generic bot delivery. Repositories retain correctness tests, release requirements and artifacts. Atlas owns documentation-manifest validation and Website publication coordination. Adopted commit and publish paths must work without Atlas.

Never commit credentials or private policy terms, including in fixtures, filenames, diagnostics or artifacts. Policy is supplied from protected configuration outside the repository. Candidate ignore files and comments cannot override organization rules. Exceptions are trusted policy entries bound to an exact rule, location and content digest.

Candidate Git objects are data. While private policy is available, never check out candidate files or execute candidate scripts, actions, build configuration, filters or tools. Missing policy, incomplete objects, ambiguous results and invalid signatures fail closed. A verified receipt must cause zero scanner invocations.

Run `cargo test --locked`, `cargo fmt --all --check` and `cargo clippy --all-targets --locked -- -D warnings`. Security regression tests must fail when their guard is removed; record mutation evidence. Use the existing `b10x-bot[bot]` identity for delivery. Release bare annotated version tags only after the gate; verify the GitHub release and binary/checksum artifacts before adopting consumers.
