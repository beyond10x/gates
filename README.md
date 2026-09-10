# Gates

Common security and privacy checks, signed local evidence, and bot delivery for Beyond10x repositories. The Rust CLI and reusable GitHub workflow operate without Atlas. Repositories retain their correctness tests, release requirements and artifacts; Atlas coordinates documentation publication independently.

Install the published Linux x86-64 static binary from the [release](https://github.com/beyond10x/gates/releases), verify it against the release checksums, and put it on `PATH` as `b10x-gates`. Other Unix platforms can build with `cargo install --locked --path .`. Run `b10x-gates bootstrap --directory "$HOME/.config/b10x/gates/bin"` to download the pinned Gitleaks 8.30.1 published binary with its fixed SHA-256 checksum.

## Local use

An administrator supplies the protected policy and enrolls the public key printed by `b10x-gates keygen --output <protected-key-file>`. The policy and signing key stay outside candidate source, owned by the current user and unreadable by other users. `B10X_GATES_POLICY`, `B10X_GATES_KEY` and `B10X_GATES_GITLEAKS` select nondefault paths. Never send a private key to CI.

```console
b10x-gates --repository beyond10x/eventlog install
b10x-gates bot -- commit -m "fix: describe the change"
b10x-gates --repository beyond10x/eventlog check --receipt "$HOME/.local/state/b10x/gates/candidate.json"
b10x-gates --repository beyond10x/eventlog verify --receipt "$HOME/.local/state/b10x/gates/candidate.json"
b10x-gates --repository beyond10x/eventlog publish --receipt "$HOME/.local/state/b10x/gates/candidate.json" --remote-ref refs/heads/fix-example
```

`check` retains a signed receipt and reuses it on retry when it still matches. `verify` invokes no scanners. `publish` verifies the retained receipt, optionally pushes its exact commit, then creates a bot-owned check containing only signed successful evidence. A failed network publication retains the receipt. An enrolled signer is a trusted local runner: its signature establishes origin and integrity, not hardware attestation. Revoking a signer or changing its repository grants invalidates existing evidence.

`install` coordinates `pre-commit`, `commit-msg` and `pre-push` with existing hooks, including worktree hooks. Existing hooks run first, then the gates inspect their final index/message. Reinstallation preserves the chain. During an authorized migration, `--retire-pre-push-sha256 <exact-old-binary-digest>` retires only that identified pre-push guard; unrelated hooks remain active. No candidate file controls this selection. Hooks are local prevention, not remote authority: GitHub enforcement remains required.

Before committing, the index is scanned independently of unstaged files. Before pushing, every commit since the trusted adoption baseline is inspected, including intermediate commits later deleted from the tip. Push destinations must match the enrolled repository, and directly introduced commits retain the exact organization bot author and committer. Use `--tag <ref>` with `check`, `verify` and `publish` when an annotated tag is part of the evidence; pre-push also inspects tags automatically.

## What is checked

- Gitleaks 8.30.1 scans file bytes, filenames, commit messages and metadata, and annotated tags. The scanner uses its pinned default rules, a trusted explicit configuration, an empty ignore file, and `--ignore-gitleaks-allow --redact=100`. Candidate ignore files and inline comments cannot disable it.
- A private literal policy checks forbidden associations and identifiers without printing those terms. Linux and macOS home paths and Windows profile paths are rejected, including bare home directories. Portable `$HOME`, `${HOME}` and XDG placeholders are accepted.
- Workflow action revisions must be exact commits or Docker digests. Workflow permissions must be explicitly declared.
- Planning files, generated files, journals, symlink target bytes and all other tracked blobs are included. Git attributes, hooks, filters, build configuration and candidate tools are never executed by the scanner. Submodules, incomplete history, non-UTF-8 filenames and inputs beyond the documented limits fail closed.

An adoption baseline is an exact trusted commit, not a candidate-controlled file. `audit --output <protected-report>` reports findings in that baseline tree separately. Historical exceptions require the exact repository, rule, location, line and content SHA-256 in the protected policy. Single-line privacy rules bind that line's bytes; secret and workflow exceptions bind the entire unit because they can span lines. Changed lines, moved locations and new occurrences require new review. Unchanged files inherited from the baseline are not new violations. No history is rewritten.

The first version reads full changed blobs per new commit, with a 64 MiB per-blob and 256 MiB candidate limit. It deliberately fails instead of silently skipping unsupported content. It does not reuse repository-specific tests or declare a deployment or release complete.

## GitHub enforcement

Adopters call `.github/workflows/common.yml` at an immutable Gates commit from a base-branch `pull_request_target` workflow, and pass only the selected-repository organization secret `B10X_GATES_POLICY`. The same check runs on integrated branch/tag pushes. The job downloads a fixed-checksum Gates binary and pinned Gitleaks binary, then fetches candidate objects into a fresh bare repository. It never checks out the candidate. Private policy is available only to this trusted step, whose children cannot execute candidate code.

The workflow first retrieves bot-published evidence. It verifies Ed25519 signatures, authorized public keys, repository name and immutable numeric id, adoption baseline, exact head, complete commit/tag and object manifest, scanner/tool versions, public/private policy digests and the complete result roster. A valid receipt causes **zero scanner invocations**. Missing, malformed, tampered, incomplete or stale evidence runs the common scanners. Missing policy fails closed.

Require the resulting `Security and privacy` check before integration, retain repository correctness checks separately, and enable GitHub secret scanning and push protection where supported. Initial adoption installs the caller after local verification, observes its first successful main run, then enables the required check. Fork workflows must never receive private policy through a candidate checkout or candidate action.

The policy wire model is strict JSON: `version`, random `nonce`, `forbidden_literals`, `repositories` (numeric `id` and exact `baseline`), `signers` (Ed25519 `public_key` and explicit `repositories` grants), and bounded `exceptions`. Actual private values have no public example. The nonce prevents the published policy digest from becoming a dictionary oracle. Policy updates are administered through protected configuration and selected-repository secrets, without contacting Atlas at runtime.

## Development and releases

```console
cargo build --locked
target/debug/b10x-gates bootstrap --directory "$HOME/.cache/b10x-gates/scanner"
export B10X_GATES_GITLEAKS="$HOME/.cache/b10x-gates/scanner/gitleaks"
cargo test --locked
cargo fmt --all --check
cargo clippy --all-targets --locked -- -D warnings
```

The real-scanner tests fail if Gitleaks is unavailable; they never silently skip. Tests cover index isolation, intermediate commits, metadata/tags, suppression attacks, private-output redaction, hostile candidate files, hook chaining, cryptographic rejection and zero-invocation reuse. ESS models the signed receipt under `ess/`.

`cargo run --locked -- gate` performs the complete repository gate and installs the pinned scanner if missing; CI delegates to this same Rust command.

Release only from gated `main` with a bare annotated version tag. Publish the static Linux binary and `SHA256SUMS`, verify both after downloading them, and verify the GitHub release author is the organization bot before pinning consumers. Build release binaries with Rust source-path remapping and scan them for private provenance. Documentation publication and downstream releases are separate operations.

<!-- b10x-docs:start -->
## Documentation

[Gates documentation](https://beyond10x.github.io/docs/gates/) · [Start](https://beyond10x.github.io/) · [Ecosystem](https://beyond10x.github.io/ecosystem/) · [Impact](https://beyond10x.github.io/changes/) · [Releases](https://beyond10x.github.io/releases/)
<!-- b10x-docs:end -->
