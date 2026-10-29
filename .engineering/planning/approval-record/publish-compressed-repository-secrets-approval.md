---
format: aep.planning-md/3
id: approval-record:publish-compressed-repository-secrets-approval
kind: approval-record
status: draft
title: Orchestrator approved compressed repository secret targets and the next gates release
relations:
- decides: story:publish-compressed-repository-secrets
revision: 2
---
## Who decided

The monitoring session `b10x-chef-orchestrator`, under the grant in the workspace instructions
(a message from it naming a class-C item counts as the operator's approval). Its message to
the `gates` session on 2026-10-29 (item D191):

> It is approved under the grant in ~/beyond10x/CLAUDE.md (class C: a commit, PR, merge and
> release through the repository's own bot route and process).

> a `compressed: Vec<String>` field on `Targets`; serde-default it, so existing publish.json
> files still parse; for each listed `owner/repo`, publish writes the full policy as a
> repository secret `B10X_GATES_POLICY_GZ`, gzip then base64, the same encoding CI reads.
> Then it reads the secret back the way publish already verifies its other targets. The dry
> run lists these targets, and `--apply` writes them

> Do NOT add the repositories to ~/.config/b10x/gates/publish.json and do NOT run publish
> --apply: b10x-atlas does that after the release.

## Decided

Implement `story:publish-compressed-repository-secrets`, merge it into `main` through the bot
route, and release the next gates patch version through this repository's process.

Taken by the `gates` session inside the item: a listed repository must be enrolled in the
policy and listed once, as `sliced` repositories must be enrolled, so a typo cannot send the
whole policy to a repository the policy does not know.
