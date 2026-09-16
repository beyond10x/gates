# Gates

Common security and privacy checks, signed local evidence, and bot delivery for Beyond10x repositories. The Rust CLI and reusable GitHub workflow operate without Atlas. Repositories retain their correctness tests, release requirements and artifacts; Atlas coordinates documentation publication independently.

Install the published Linux x86-64 static binary from the [release](https://github.com/beyond10x/gates/releases), verify it against the release checksums, and put it on `PATH` as `b10x-gates`. Other Unix platforms can build with `cargo install --locked --path .`. Run `b10x-gates bootstrap --directory "$HOME/.config/b10x/gates/bin"` to download the pinned Gitleaks 8.30.1 published binary with its fixed SHA-256 checksum.

## Local use

The policy lives in its own private repository, cloned beside the repositories it guards, and is never copied into candidate source. `install` canonicalises `--policy` to an absolute path and narrows the file to owner-only, so a fresh clone made with the usual umask is accepted and every linked worktree resolves the same file. An administrator enrolls the public key printed by `b10x-gates keygen --output <protected-key-file>`. The policy and signing key stay owned by the current user and unreadable by other users. `B10X_GATES_POLICY`, `B10X_GATES_KEY` and `B10X_GATES_GITLEAKS` select nondefault paths. Never send a private key to CI.

```bash
b10x-gates --repository beyond10x/eventlog --policy ../gates-policy/policy.json install
b10x-gates bot -- commit -m "fix: describe the change"
b10x-gates --repository beyond10x/eventlog check --receipt "$HOME/.local/state/b10x/gates/candidate.json"
b10x-gates --repository beyond10x/eventlog verify --receipt "$HOME/.local/state/b10x/gates/candidate.json"
b10x-gates --repository beyond10x/eventlog publish --receipt "$HOME/.local/state/b10x/gates/candidate.json" --remote-ref refs/heads/fix-example
```

`check` retains a signed receipt and reuses it on retry when it still matches. `verify` invokes no scanners. `publish` verifies the retained receipt, optionally pushes its exact commit, then creates a bot-owned check containing only signed successful evidence. A failed network publication retains the receipt. An enrolled signer is a trusted local runner: its signature establishes origin and integrity, not hardware attestation. Revoking a signer or changing its repository grants invalidates existing evidence.

`install` coordinates `pre-commit`, `commit-msg` and `pre-push` with existing hooks, including worktree hooks. Existing hooks run first, then the gates inspect their final index/message. Reinstallation preserves the chain. One copy of the binary is written per repository and the thirteen hook names are hardlinks to it, so an installation costs one binary rather than thirteen. The link holds that exact inode, which is what pins a hook against a binary changing under a commit in flight; the cost is that `cargo install --force` does not upgrade installed hooks, and `install` must be re-run in every repository. `config.json` records the version that installed them. During an authorized migration, `--retire-pre-push-sha256 <exact-old-binary-digest>` retires only that identified pre-push guard; unrelated hooks remain active. No candidate file controls this selection. Local commits require the exact bot author and committer. Hooks are local prevention, not remote authority: GitHub enforcement remains required.

Before committing, the index is scanned independently of unstaged files. Before pushing, every commit since the trusted adoption baseline is inspected, including intermediate commits later deleted from the tip. Push destinations must match the enrolled repository, and directly introduced commits retain the exact organization bot author and committer. Use `--tag <ref>` with `check`, `verify` and `publish` when an annotated tag is part of the evidence; pre-push also inspects tags automatically.

## What is checked

- Gitleaks 8.30.1 scans file bytes, filenames, commit messages and metadata, and annotated tags. The scanner uses its pinned default rules, a trusted explicit configuration, an empty ignore file, and `--ignore-gitleaks-allow --redact=100`. Candidate ignore files and inline comments cannot disable it.
- A private policy checks forbidden associations and identifiers without printing those terms. `forbidden_literals` are matched as escaped case-insensitive substrings; `forbidden_patterns` are case-insensitive regular expressions, for rules a literal cannot express such as a separator or case variant, a bare surname or an adopter's name. `allow_patterns` admit an occurrence only when the pattern's `(?P<admit>...)` group **contains** it, so a real upstream citation — a dependency URL, a cargo `git` source, an ssh remote — need not be falsified, while a markdown link's label, a query string or prose on the same line is still refused. An allowance without that group is refused, as is any rule that matches an ordinary line or the empty one. Allowances never reach `personal-paths`.
- Linux and macOS home paths and Windows profile paths are rejected, including bare home directories, and in every delimiter this organization writes: backticks, markdown table cells, emphasis markers, quotes, link targets and `file://`. Portable `$HOME`, `${HOME}` and XDG placeholders are accepted. A path that merely contains the word `home`, and a REST route such as `/users/{id}`, are not personal paths: the first segment must end the reference or be followed by `/`, and `/Users/` is matched case-sensitively. Unicode format characters are removed before matching, and a literal a soft wrap split over two lines is still caught.
- Workflow action revisions must be exact commits or Docker digests. Workflow permissions must be explicitly declared.
- Planning files, generated files, journals, symlink target bytes and all other tracked blobs are included. Git attributes, hooks, filters, build configuration and candidate tools are never executed by the scanner. Submodules, incomplete history, non-UTF-8 filenames and inputs beyond the documented limits fail closed.

A change is answerable for the lines it introduces, not for the file it lands in. Every changed blob is scanned whole, and a finding whose exact line is already present in that path's previous version is inherited rather than new — so editing one line of a document that already carries a hundred findings is admitted, while adding the hundred-and-first is refused. This applies to the privacy rules and to secrets. A unit with a NUL byte in its first 8 KiB is left to the secret scanner; an archive or an image carries no prose.

An adoption baseline is an exact trusted commit, not a candidate-controlled file. `audit --output <protected-report>` reports findings in that baseline tree separately. Historical exceptions require the exact repository, rule, location, line and content SHA-256 in the protected policy. Single-line privacy rules bind that line's bytes; secret and workflow exceptions bind the entire unit because they can span lines. Changed lines, moved locations and new occurrences require new review. Unchanged files inherited from the baseline are not new violations. No history is rewritten.

The first version reads full changed blobs per new commit, with a 64 MiB per-blob and 256 MiB candidate limit. It deliberately fails instead of silently skipping unsupported content. It does not reuse repository-specific tests or declare a deployment or release complete.

## GitHub enforcement

Adopters call `.github/workflows/common.yml` at an immutable Gates commit from a base-branch `pull_request_target` workflow, and pass only the selected-repository organization secret `B10X_GATES_POLICY`. The same check runs on integrated branch/tag pushes. The job downloads a fixed-checksum Gates binary and pinned Gitleaks binary, then fetches candidate objects into a fresh bare repository using the workflow token, supplied through the environment so it never appears in argv. On a plan where organization secrets reach public repositories only, a private adopter needs the policy as a repository secret of the same name. It never checks out the candidate. Private policy is available only to this trusted step, whose children cannot execute candidate code.

The workflow first retrieves bot-published evidence. It verifies Ed25519 signatures, authorized public keys, repository name and immutable numeric id, adoption baseline, exact head, complete commit/tag and object manifest, scanner/tool versions, public/private policy digests and the complete result roster. A valid receipt causes **zero scanner invocations**. Missing, malformed, tampered, incomplete or stale evidence runs the common scanners. Missing policy fails closed.

## Content that never reaches a commit

A pull request body, an issue comment, a release note and a chat message are published without passing through Git, so no hook sees them. The delivery verbs scan before they send: `gh -- <args>` scans its arguments, `api --input <file>` scans the body file, and `scan-text <file>...` refuses any file that breaks a rule, for publishers that are not `gh`. Each refuses with rule coordinates and never echoes the matched text. A missing policy is a refusal, not an unscanned send.

The boundary: a raw `gh` or `curl` invoked outside `b10x-gates` is unguarded. Route delivery through the verbs.

Require the resulting `Security and privacy` check before integration, retain repository correctness checks separately, and enable GitHub secret scanning and push protection where supported. Initial adoption installs the caller after local verification, observes its first successful main run, then enables the required check. Fork workflows must never receive private policy through a candidate checkout or candidate action.

The policy wire model is strict JSON: `version` (2), random `nonce`, `forbidden_literals`, `forbidden_patterns`, `allow_patterns`, `repositories` (numeric `id` and exact `baseline`), `signers` (Ed25519 `public_key` and explicit `repositories` grants), and bounded `exceptions`. Actual private values have no public example. The nonce prevents the published policy digest from becoming a dictionary oracle. A policy whose pattern does not compile is refused at load, never at first scan. Policy updates arrive as a commit in the private policy repository and reach CI as an organization secret; `policy except --findings <report>` appends reported findings as exceptions so an admitted occurrence is reviewed as a diff rather than hand-edited; `--any-line` binds the content but not the line, and `--any-content` binds a location whose file is regenerated on every build. An exception location ending in `*` covers a tree. The organization secret is limited to 48 KiB, so set it from the compact form of the policy (`jq -c .`); the policy digest is computed from the parsed document and does not change with formatting. Nothing contacts Atlas at runtime.

Every commit after the trusted adoption baseline must have the exact raw Git author `b10x-bot[bot] <316511680+b10x-bot[bot]@users.noreply.github.com>`, `github-actions[bot] <41898282+github-actions[bot]@users.noreply.github.com>` or `dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>`. The third is admissible as an author only, so a dependency update can be reviewed and merged; it is scanned like any other change. Candidate construction enforces this before scanning or receipt reuse, including intermediate commits and merged side branches. Mailmaps, display names, duplicate author headers and other bot names cannot authorize a commit. GitHub merge committers remain admissible to the common author check; direct local delivery still requires the exact organization bot as both author and committer. Git metadata establishes this allowlist, while App-only branch authority establishes who can publish it.

A version 2 policy is unreadable by an earlier binary: the wire model is `deny_unknown_fields`, so 0.1.2 refuses it with "policy format invalid" and the gate fails closed. Release and roll out 0.1.3 to every caller **before** setting the organization secret to a version 2 policy; local hooks read the policy file directly and can move first.

Version 0.1.3 adds `forbidden_patterns` and `allow_patterns`, widens the personal-path boundary, and scans published content in the delivery verbs; it requires policy version 2 and invalidates earlier receipts through the Gates version and private-policy digest. Version 0.1.1 added the `commit-authorship` result and invalidated earlier receipts through the Gates version and public-policy digest. Version 0.1.2 changes no check, policy field or receipt format, and invalidates receipts retained under 0.1.1 through the Gates version alone. Historical baseline auditing remains separate.

## Development and releases

```bash
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
