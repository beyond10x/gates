# Initial adoption

## Authorship enforcement

[Gates 0.1.1](https://github.com/beyond10x/gates/releases/tag/0.1.1) adds mandatory raw commit-author
admission before scanning or receipt reuse. Its exact tag passed correctness and shared checks,
and the downloaded static binary matched its published checksum. The coordinated update for the
four existing adopters pins workflow commit `547c6bc58d734e679f21bdeeb365f7dcc88059b1`, which downloads
that verified release. Local hooks also reject non-bot authors and committers at commit creation.
The policy baselines below remain unchanged; prior receipts become stale.

## Original rollout

Gates 0.1.0 was published and its tag checks and downloaded release assets verified before
Eventlog, ESS and AEP pinned reusable workflow commit
`4317ac7561e7307a6426212f1929b6a8259fc915`.

The protected policy declares these exact pre-adoption baselines:

| Repository | Baseline |
|---|---|
| beyond10x/gates | `ddf3c550fe489e0964d30fe9784727e5e694746c` |
| beyond10x/eventlog | `7d6bedc738b6037c7a1ba5218bc2a0d3271878c3` |
| beyond10x/ess | `24d2fe714958c8cde63ea78122c31e28bcc682bc` |
| beyond10x/aep | `9939b0d1b83747c216a79f127c3f2dd6936f7990` |

ESS received a concurrent source update before adoption, so its baseline was advanced to that
published commit and its planning journal was preserved during integration. Historical findings
are retained only in protected local reports. Exceptions identify exact rules, locations, lines
and content hashes. No source history was rewritten. The policy is an organization secret selected
only for these four repositories; enrolled private signing keys remain local.

GitHub secret scanning and push protection are enabled. Coordinated local hooks preserve existing
worktree hooks and replace only the explicitly identified legacy pre-push binary. Bot commits,
signed checks and publication were exercised with Atlas unavailable. Changes to policy invalidate
retained receipts and require fresh evidence.

During first adoption, the trusted base branch does not yet contain the reusable-workflow caller.
Bootstrap that caller using verified local common checks and repository correctness, then verify
the initial main-branch shared run and require its exact GitHub check before further integration.
Repository correctness, release artifacts and documentation delivery keep their separate owners.
