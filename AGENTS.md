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

<!-- b10x-docs-operations:start -->
## Public documentation operations

This repository owns the public source and presentation allowlist in `b10x.docs.yaml`. The generated credential-free `.github/workflows/b10x-docs-bundle.yml` passively packages only those declared files for the exact successful `main` commit; it must never run repository code. Atlas selects the latest successful bundle with every other catalog source, and Website plus Docs System own rendering, shared components, search, and feeds. Do not add a standalone docs deployer or put App credentials in this public repository. If Atlas catalogs a former Pages workflow, that file remains repository-owned validation: preserve its bespoke checks while keeping exact read-only permissions, an unconditional pull-request trigger, and no deployment primitives. Project Pages at `/gates/` is only the generated stable redirect façade in `.github/workflows/b10x-docs-pages.yml`; content-only publication never rebuilds it.

From the complete organization workspace, verify the contract with a clean Atlas checkout at the current remote `main`. Set `B10X_ATLAS_CHECKOUT` to a managed Atlas worktree when the primary checkout is dirty or stale; never infer command availability from the primary alone.

```bash
atlas_checkout="${B10X_ATLAS_CHECKOUT:-atlas}"
atlas_head="$(git -C "$atlas_checkout" rev-parse HEAD)"
atlas_main="$(git -C "$atlas_checkout" ls-remote origin refs/heads/main | awk '{print $1}')"
test -z "$(git -C "$atlas_checkout" status --porcelain)"
test "$atlas_head" = "$atlas_main"
cargo run --manifest-path "$atlas_checkout/Cargo.toml" --locked -q -- \
  --store "$atlas_checkout/catalog/store" docs reconcile --workspace . --check
```

Keep internal plans, stories, ADRs, decisions, worklogs, security material, and research out of the public allowlist unless a repository authority explicitly declares them public.
<!-- b10x-docs-operations:end -->
