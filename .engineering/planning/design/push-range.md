---
format: aep.planning-md/3
id: design:push-range
kind: design
status: draft
title: Check only the commits a push adds to the published default branch
summary: 'Revision 3: provenance of the check run on B plus a range annotation (no tag confusion, no receipt reuse, policy digest), audit freshness under 48 h, a new first story closing writes to the policy repository; boundary and open questions Q2-Q4'
relations:
- designs: story:push-range
- designs: story:ci-committer-pr-bound
- designs: story:history-audit-schedule
- designs: story:consumer-pins-trusted
- designs: story:api-policy-repository-writes
revision: 5
---
## Verdict (revision 3)

**Ready after the changes of the second adversary review, all adopted here. Two questions stay with
the owner (Q3, Q4), and while they are open the design protects against less than it would; see
"The boundary".**

Revision 1 trusted the published default branch because two rulesets exist. That was wrong (G1 to
G7 below). Revision 2 trusts a default-branch commit `B` only through the **provenance of the check
run on `B`**. Revision 3 keeps that rule and closes the three gaps the second review found:

- **N1.** A tag named like the default branch, created and deleted, left a run the rule could not
  tell from a branch push. The trusted binary now writes a range annotation naming the ref it
  checked, and every annotated default-branch push run on `B` must be green.
- **N2.** The default-branch push run could verify a forged receipt instead of scanning. It now
  never reuses a receipt, and the committer check runs in admission, ahead of any reuse.
- **N3.** The scheduled audit could be edited and muted by the bot. Its repository list now comes
  from the policy, and `B` is trusted only while that repository's audit is green and younger than
  48 hours.

A default-branch commit `B` is trusted only when:

- the check run on `B` is the canonical shared-gates caller, calling a Gates `common.yml` commit on
  the trusted list;
- every run of that check on `B` whose range annotation names the default branch is a push run that
  concluded green, checked `baseline..B` without reusing a receipt, under the same policy digest as
  the local policy;
- the repository's history audit is green and younger than 48 hours.

Every other case uses the enrolled baseline range, exactly as 0.1.28 does.

What changes for a repository that qualifies:

- **Removed:** the class "a GitHub-written commit on the default branch that the local merge proof
  cannot prove", which is spindle's case.
- **Not removed:** content and authorship problems already on the default branch. They keep the
  default branch's check red, so the repository falls back and stays stopped. That is the honest
  state. It is repaired with exact policy exceptions, never by moving a baseline.

The owner decided Q1 on 2026-11-24: **A**. A repository that does not qualify keeps the baseline
range.

## The boundary (finding N4)

Revision 2 stated two conditions, C1 (no session chooses the policy the trusted job reads) and C2
(the trusted list is only as safe as the policy file). The second review showed both are too narrow.
Every session runs as the same OS user that can read or use:

- the bot App's private key, which mints an installation token with every permission the App has
  and skips every verb guard;
- the receipt signing key, which signs any receipt;
- the local clone of the policy repository, files mode 600 owned by that user, which holds
  `policy.json` and will hold the trusted list;
- the owner's `gh` login on the keyring, with scopes `admin:org`, `repo`, `workflow` and
  `delete_repo`: it can set repository secrets, edit rulesets, delete workflow runs and push the
  policy repository.

The design protects against a session that acts only through the guarded `b10x-gates` verbs. It
does **not** protect against a session that reads those keys, edits the policy clone as a plain
file, or uses the owner's login. On a single-UID machine no code can enforce that; it is a rule for
sessions, and the owner's answer to Q4 says what the boundary is.

**What the design does not protect against while Q3 and Q4 are open:**

- Until `story:api-policy-repository-writes` ships, any session can write `policy.json` or the trusted
  list in the policy repository through `api` or `gh -- api`. After it ships, the verb route is
  closed, but a token minted with the App key still writes there while the App is installed on it
  (Q3).
- A session that edits the local policy clone changes what its own local gate trusts, with no
  GitHub write at all.
- A session with the signing key can make a local push or a pull-request run skip the scan by a
  forged receipt, as in 0.1.28. Revision 3 only takes the key out of the trust chain of `B` (N2).
- A session with the owner's login can set a repository secret that shadows the organization policy
  secret (C1), so the trusted job reads a policy of the session's choice; it can delete a red
  workflow run, so "every annotated run is green" no longer sees it; and it can edit rulesets.
- C1 holds for the App today: the App gets 403 on `actions/secrets/public-key` and on the
  organization's secrets (verified by the second review). Q2 decides whether that stays.

## Question

Today every push re-judges every commit from the repository's enrolled baseline. One commit on the
default branch that the local gate does not accept stops every later push until someone moves the
baseline by hand. The owner picked on 2026-11-24 "A: check only new commits". The case that
prompted it: three single-parent commits on spindle's `main`, with the bot as author and GitHub as
committer, were refused by the local pre-push walk with "a commit on the pull request head line is
neither the bot's nor a branch update" (`src/published_merge.rs:764-768`). Spindle's baseline was
moved on 2026-11-24 to repair it.

## Where the range is computed today (0.1.28, `ba05649`)

Unchanged from revision 1; the adversary checked every line.

| # | path | file:line |
|---|---|---|
| 1 | candidate build | `src/git.rs:801-946`; ancestry `:814-822`; `rev-list <baseline>..<head>` `:823-832`; author admission `:856-859`; `Binding.baseline` `:934` |
| 2 | `check`, `verify`, `publish` | `src/main.rs:676-677`; `publish` proof `:732-740` → `src/delivery.rs:52-61` → `src/published_merge.rs:54-95` |
| 3 | pre-push (`bot -- push`, `publish --remote-ref`) | `src/hooks.rs:264-307`; lazy API read `src/delivery.rs:63-78` |
| 4 | ancestor receipt reuse | `src/evidence.rs:215-230` → `src/git.rs:791-799` |
| 5 | receipt statement | `src/evidence.rs:17`, `:39-41`, `:92-96`, `:107`, `:120-145` |
| 6 | `ci` | `src/delivery.rs:976-982`, `:1029`, `:1080`; `src/main.rs:571-591` |
| 7 | `audit` | `src/main.rs:658-666` → `src/git.rs:982-991` (baseline tree only) |
| 8 | documentation | `README.md:19`, `:23`, `:49`, `:57`, `:83` |

## The range annotation (story 1; N1, N2, N9)

Every `ci` run of the binary writes one annotation on its own job:

```
::notice title=b10x-gates range::event=<event> ref=<event.ref> base=<bound id> head=<head id> reused=<true|false> policy=<private policy digest>
```

- `ref` is the event's `ref` (`refs/heads/<b>`, `refs/tags/<t>`, `refs/pull/<n>/head`), never the
  run's `head_branch`. A tag named like the default branch therefore says `refs/tags/<default>`.
- `base` is the bound the run used: the baseline on a default-branch push, `D` elsewhere.
- `reused` says whether a receipt replaced the scan. On a default-branch push it is always `false`.
- `policy` is the private policy digest that receipts already carry (`src/evidence.rs:27`,
  `src/policy.rs:157`), so the local gate can tell a CI policy that differs from its own (N9).

Only the trusted binary writes it, and a canonical caller cannot add a step to its job (test 3), so
the annotation on that check run comes from the binary.

## The trusted bound `B` (local paths, story 2)

### Precondition: rulesets (R5, O1, O3)

- Read `GET /repos/<r>` and check the numeric id against the policy. Then read
  `GET /repos/<r>/rules/branches/<default>`. GitHub resolves the include and exclude patterns and
  returns only active rules, each with its `ruleset_id`.
- Require both of these:
  - the `creation`/`update`/`deletion`/`non_fast_forward` rules come from the exact
    `b10x-bot-branch-authority` ruleset (today's `verify_branch_authority`);
  - a `required_status_checks` rule lists `{context: "common / Security and privacy",
    integration_id: 15368}`, and its ruleset, read by id, has `enforcement: active` and a
    `bypass_actors` field that is **present** and empty. An absent field does not qualify.
- Only the rulesets these rules name are read. An unrelated unreadable ruleset changes nothing.

### Provenance of the check on `B` (G1, G5, N1, N2, N6, N9)

`T` is the tip of the default branch, from `GET /repos/<r>/git/ref/heads/<default>`.

**Candidates.** `B` is the newest commit, walking `T`'s first-parent line back at most 20 commits,
that passes every test below. With none, the bound is the baseline. Walking back covers the minutes
after a merge, while the push run on `T` is still pending. Commits between such a `B` and `T` are in
the range and get today's proof, so a spindle-shaped commit merged in that window still refuses
until the run on `T` is green.

**Tests for one candidate `C`:**

1. Every check run on `C` named `common / Security and privacy` (`GET
   /repos/<r>/commits/<C>/check-runs?check_name=…&filter=all`, paginated):
   - comes from app 15368;
   - its check suite has exactly one workflow run (`GET /repos/<r>/actions/runs?check_suite_id=…`);
   - that run's `path` is `.github/workflows/shared-gates.yml`;
   - that run's `referenced_workflows` is exactly one entry,
     `beyond10x/gates/.github/workflows/common.yml@<sha>`, with `<sha>` on the trusted list.

   A run with that name from anywhere else means forgery or drift, so the candidate fails. This
   covers another workflow file, a check from the App, another pin, or a second referenced workflow.
2. The range annotations (`GET /repos/<r>/check-runs/<id>/annotations` for each run of test 1):
   - at least one run carries an annotation with `ref=refs/heads/<default>`;
   - **every** run whose annotation names that ref, at its newest attempt, concluded `success`, and
     so did its workflow run; a pending one fails the candidate;
   - each of those has `event=push`, run `event: push`, `head=C`, `base=` the local baseline,
     `reused=false` and `policy=` the digest of the local policy. A different `policy` fails the
     candidate with its own reason line (N9), never silently;
   - runs whose annotation names a tag, a pull request or a merge group are only held to test 1.
     Their range is not the baseline range. Counting a merge-group run bounded by `D` would reopen
     G3; the queue's merge triggers a push run on the default branch anyway.
   - a run of test 1 with no range annotation fails the candidate.
3. `.github/workflows/shared-gates.yml` at `C` has the canonical shape. It is read locally as a blob
   and parsed as data, never run. The shape is an **allowlist** (N6):
   - `jobs` holds exactly one job, `common`;
   - that job's keys are exactly `uses` and `secrets`, nothing else (no `with`, `if`, `name`,
     `needs`, `strategy`, `concurrency`, `permissions`);
   - `uses` is exactly the trusted ref;
   - `secrets` is a map whose only keys are `B10X_GATES_POLICY_GZ` and/or `B10X_GATES_POLICY`, each
     with the value `${{ secrets.<same name> }}`.

   This closes a caller that calls the trusted `common.yml` under another job id and adds a plain
   job named `common / Security and privacy` that runs `true`. Every caller seen on 2026-11-24 has a
   job of this shape (43 of 43, adversary reads).
4. `C` descends from the baseline. Otherwise the candidate fails, and with it every older one (R6).

**Audit freshness (N3).** Once a candidate passes, the repository's history audit (story 3) must be
fresh. The newest completed run of `.github/workflows/history-audit.yml` in this repository
(`schedule` or `workflow_dispatch`) is read through the API and must:

- be a run of that path, from app 15368, whose workflow file at the run's commit is the same blob as
  at a Gates commit on the trusted list;
- have the job for `<r>` concluded `success`, with an annotation `b10x-gates audit` naming `<r>`,
  `base=` the local baseline, a `head` `T'` that `B` descends from, `findings=0`, and the local policy
  digest;
- have completed less than 48 hours ago.

Otherwise the bound is the baseline. An audit that a bot change muted, emptied or stopped therefore
becomes a fallback, which every session's push shows. (The review's wording asks for `T'` to descend
from `B`; that needs an audit after every merge. The design takes `B` descends from `T'`: the audit
covers `baseline..T'`, and `B`'s own push run covers `baseline..B`.)

**Fetch.** `B` is fetched **by id** through the bot remote when it is not in the local store. No ref
is written and none is trusted. A failed fetch selects the baseline (R2).

**Any read failure selects the baseline (R1).** This includes 404/409 on the default ref, 403 on a
private repository, a 5xx after retries, and a page that does not parse. A wider range is never
weaker, so a refusal here would add noise and no safety. The baseline is also selected when the
trusted list is missing or empty, and when no App credential is readable (`check` and `verify`
offline).

**Reads and the cache (N7).** One candidate costs 1 + 2k reads, where k is the number of check runs
with the check's name on it (tag run, branch run, re-runs each sit in their own suite), plus pages.
A red tip walks up to 20 candidates. With many sessions pushing, the App's per-installation rate
limit is the ceiling. So each verdict for (repository, `C`, trusted-list digest, policy digest) is
cached locally, owner-only, for 5 minutes:

- a cache is only a hint: a miss reads again;
- a hit is used only after one read of the check runs on `T` shows no run newer than the entry;
- a forged entry needs a local file write, which gives a session nothing beyond the boundary above.

**What a session sees when its repository does not qualify:** one line, then today's walk.

```
b10x-gates: bound=baseline for <owner>/<repo>: <reason>
```

The reasons:

- `the check on <C10> ran common.yml@<sha10>, not a trusted Gates workflow; move the pin in .github/workflows/shared-gates.yml to <newest trusted sha>`
- `no successful push run of shared-gates.yml on the last 20 commits of <default>`
- `a default-branch run on <C10> is not green`
- `the default-branch run on <C10> has no range annotation, or covered <base10>, or reused a receipt`
- `the CI policy differs from the local policy (run on <C10>)`
- `shared-gates.yml at <C10> is not the canonical caller`
- `history audit for <owner>/<repo> is not green or older than 48 hours`
- `no required common check on <default>`
- `read failed: GET <path>: <status>`
- `trusted workflow list missing or empty`

**After the walk (G7):** the pre-push hook reads `T` again. If the new tip does not descend from
`B` (a rewind in between), it repeats the walk with the baseline range.

### What the trusted list is and how it is kept

- **File.** `trusted-workflows.json` in the policy repository, beside `policy.json`. It is read with
  the same owner-only protected read. It is a list of Gates commit ids. It is **not** a field of
  `policy.json`, because older binaries read the policy with `deny_unknown_fields`, and a new field
  would turn CI red on every consumer that pins a binary older than the one that reads it (37 of the
  43 qualifying ones). `ci` does not need the list.
- **Admission.** A Gates commit goes on the list only when the binary its `common.yml` downloads has
  everything story 1 delivers: committer admission ahead of reuse, the default-branch push on the
  baseline range without receipt reuse, the range annotation, the dispatch guard and the `event.ref`
  rule.
- **At a release.**
  1. The release commit that moves `common.yml` to the new binary is merged.
  2. The owner adds that commit id to the list in the policy repository, as a policy-repository
     commit. A session prepares the line; the owner commits it.
  3. Ids stay on the list until the owner removes one, for example after a rule fix that the old
     binary lacks.
  4. The release procedure in `README.md` (Development and releases) gains this step.
- **Switch.** The list stays empty, so no repository qualifies, until the conditions of "Order of
  work" step 5 hold.

## The range per path

| path | revision 3 |
|---|---|
| pre-push, `publish`, `check`, `verify` | `rev-list <head> --not <B>`, walked with **today's** proof: a commit not by the bot must be a proved GitHub merge on the published tip `T`, otherwise it is refused, naming it. A commit in the range is either new (and must be the bot's) or lies between `B` and `T` (and is proved as today). The head must descend from the baseline, as today. With `B` = baseline, this is exactly 0.1.28 |
| ancestor receipt reuse | rebuild the ancestor's candidate with the receipt's own `base`, verify it, count its commits as covered |
| `ci`, push of the default branch | **the baseline range, as today** (G3), and **no receipt reuse** (N2). It is recognised only by `event.ref == refs/heads/<event.repository.default_branch>`, never by `head_branch` (N8). Only a run of this kind proves `B` |
| `ci`, pull request, merge group, tag, other branch | `rev-list <head> --not <D>`, where `D` is `refs/heads/<repository.default_branch>` fetched by name from the repository URL in the run, **never** `pull_request.base.sha` or `merge_group.base_sha` (G2). If there is no `D` or the fetch fails: the baseline |
| `ci`, `workflow_dispatch` | as other branch; refused when `inputs.head` is set and differs from the run's commit `GITHUB_SHA` (N5), so a dispatch cannot give a commit a check it did not earn |
| `ci`, every event, in admission ahead of any receipt reuse | committer admitted only as exactly `b10x-bot[bot] <316511680+b10x-bot[bot]@users.noreply.github.com>` or exactly `GitHub <noreply@github.com>`, name and email both exact (G4); author as today (`src/git.rs:856-859`) |
| `audit --history` | every commit in `rev-list <T> --not <baseline>`: authorship and committer verdicts plus findings, written to the protected report; non-zero exit when any is found |

Pull requests (G2):

- **Stacked:** a pull request F→E, where E is not the default branch, is checked over `F --not D`.
  So E's own commits that are not on the default branch are checked in F's run too.
- **Base change after the check:** the checked range never depended on the base, so retargeting a
  pull request to the default branch without a new run changes nothing. If `D` only moved forward
  since the check, the checked range covers more than the merge adds.

## Receipts and evidence

- `Binding` gains `base`. `Payload.version` becomes 2, `DOMAIN` becomes `b10x.gates.receipt/2`, and
  the public digest token `all-outgoing` becomes `pushed-range-1`.
- Statement: every commit reachable from `head` and not from `base` passed, and `base` descends from
  `baseline`.
- **Acceptance rule, everywhere but the default-branch push (R3, R4):** a receipt for the same head
  and tags is accepted when its `base` is an ancestor of the path's bound and descends from the
  baseline. It is verified in full against the candidate rebuilt with **its own** `base`. Its range
  is then a superset of the path's.
  - `publish` after a merge into the default branch therefore keeps the receipt from `check`.
  - `ci` on a pull request accepts a local receipt whose `base` is behind `D`.
  - Authorship and committer admission run before this rule, so a reused receipt never skips them
    (N2, G4).
- **The default-branch push reuses no receipt (N2).** It always scans `baseline..head`. This takes
  the signing key out of the trust chain of `B`.
- 0.1.28 receipts fail `current` and are ignored, so the range is scanned. Old binaries skip version 2
  receipts (`deny_unknown_fields`) and scan.
- Pins: see story 4. Hooks are re-installed per repository after the upgrade (`README.md:21`).

## G4 on existing history: what turns red

Counted read-only on 2026-11-24 over `compare/<baseline>...main` on GitHub. Spindle was counted from
its baseline before the 2026-11-24 move (`b6c8ce7`), because its current baseline is `main`'s tip.

| repository | commits | committer bot | committer exactly GitHub | other committer | author not automation |
|---|---|---|---|---|---|
| spindle | 693 | 612 | 81 (3 with one parent) | 0 | 0 |
| gates | 215 | 187 | 28 | 0 | 0 |
| aep | 443 | 352 | 91 | 0 | 0 |
| eventlog | 370 | 314 | 56 (1 with one parent) | 0 | 0 |
| entity-runtime | 419 | 341 | 78 (1 with one parent) | 0 | 0 |
| metaharness | 39 | 39 | 0 | 0 | 0 |

The committer rule turns **nothing** red in 2,179 commits.

Where it does turn something red:

- The commit becomes a finding `commit-committer` at location `commit:<oid>`, with the SHA-256 of
  the raw commit object as its content digest.
- It is admitted only by an exact policy exception for that repository, rule, location and digest,
  added through `policy except --findings` from the `audit --history` report. That is a reviewed
  policy diff bound to one commit. No baseline moves.
- Story 1 runs the same count over all 43 qualifying repositories before its release, and lists every
  hit. Commits written by Actions with `github-actions[bot]` as committer turn red there, as wanted.
- An author outside the automation identities keeps today's hard refusal. None was found, and the
  identity ruleset's author pattern stops new ones.

## Threat cases (revision 3)

| case | caught before | caught after | where, after |
|---|---|---|---|
| A commit X written through the API onto the default branch, with a forged required check (G1) | No. The App can fast-forward the branch once a check with the right name and integration is green. | Yes | X's tip fails provenance (other path, untrusted pin, non-canonical caller, or a real run that is red because it covers `baseline..X`), so the repository falls back. The next local push refuses X, as in 0.1.28. The audit turns red. |
| A tag named like the default branch, created on a red tip and deleted (N1) | No | Yes | The tag run's annotation names `refs/tags/<default>` and does not count; the branch run stays red, and every annotated default-branch run must be green. `ci` treats the tag as a tag by `event.ref` (N8). |
| A forged receipt for `baseline..X` published as the evidence check (N2) | No | Yes | The default-branch push run reuses no receipt and scans; committer admission runs before any reuse. |
| A dispatch with `inputs.head` giving a branch tip a green check (N5) | No | Yes | `ci` refuses `inputs.head` that differs from `GITHUB_SHA`. The default-branch push run would also catch it. |
| The audit muted by a bot change: a repository dropped from its list, `continue-on-error`, the issue closed (N3) | n/a | Yes | The list comes from the policy; an audit that is not green and fresh makes the repository fall back. |
| CI runs under a policy other than the local one (N9) | No | Yes | The annotation's policy digest differs; the candidate fails with its own reason. |
| Stacked pull request carrying X (G2) | Yes. X is in `F --not D` and refused on the pull request. | n/a | |
| A person as author reaching the default branch | Partly. The identity ruleset's author email pattern, and `ci` on the pull request, stop it. | Yes | The default-branch push run (baseline range) turns red, the repository falls back, and the audit turns red. |
| A forged committer name with the bot email (G4) | Yes on trusted pins (committer admission). No on old pins. | Yes | An old pin does not qualify, so today's walk refuses it at the next push. |
| A secret, or a newly added rule, matching history on the default branch | It was scanned when added, under the rules then in force. | Yes | The default-branch push run or the audit turns red, and the repository falls back. Repair: rotation and an exact exception. No baseline move. |
| A force push of the default branch | Only the bot verb refuses it. The authority ruleset's `non_fast_forward` rule has the App bypass, and `api` does not guard `PATCH /git/refs … force`. | Yes | The new tip needs its own green baseline-range push run. A rewrite past the baseline falls back (R6). A purged commit is not under `B`, so it is judged again. Race window: see G7. |
| A pull request head line with an unacceptable commit not on the default branch | **Refused** locally and in `ci`, naming the commit | n/a | |
| A side branch merged into the candidate | Its commits not under `B` are in range and walked | n/a | |
| A repository without the rulesets, private, or on an old pin | As today (Q1 = A) | As today | |
| A session writing the policy or the trusted list through `api`, `gh -- api` or `bot -- push` | No | Yes, after `story:api-policy-repository-writes` | The verbs refuse every write naming the policy repository. |
| A session using the App key, the signing key, the policy clone as a file, or the owner's login | No | **No** | Outside the design (N4); see "The boundary" and Q3, Q4. |

**Window (G7).** Between the hook's read of `T` and the push, a rewind that purges commit Y from the
default branch would let a branch carrying Y be judged with the old `B`. The second read of `T`
after the walk narrows this to the time between that read and the push itself, usually under a
second. It needs an App force push in the same moment. Accepted.

## Findings of the adversary reviews, with dispositions

First review (revision 1):

- **G1** (forgeable required check): closed by provenance tests 1 to 3, the range annotation (N1)
  and no reuse on the default-branch push (N2). The variant through a policy secret stays outside
  the design (N4, Q2).
- **G2** (pull-request range by `base.sha`): closed by "The range per path" (`ci` bound `D`, never
  `base.sha`), including stacked pull requests and a base change.
- **G3** (default-branch `ci` narrowed): closed. The default-branch push keeps the baseline range,
  and only that run proves `B`.
- **G4** (committer never checked): closed by committer admission in `ci`, ahead of any receipt reuse
  (N2), and the exception route.
- **G5** ("passed the check" depends on the pin): closed by the trusted list, under the boundary.
- **G6** (catch-after is not a report): closed by story 3 together with audit freshness (N3).
- **G7** (rewind race): accepted and documented ("Window").
- **R1 to R6**, **O1**, **O3**, **O4**, **O6**: closed as in revision 2 (any read failure selects the
  baseline; fetch by id; acceptance rule; `rules/branches`; a rewrite falls back; tests in stories 1
  and 2). **O5**: no change needed. **O2** (rulesets prove only "now"): accepted; it relies on the
  audit, which N3 makes enforceable.
- **False claims of revision 1** (identity ruleset needs the bot committer; every commit on the
  branch passed `ci`; the ruleset refuses non-fast-forward): corrected or withdrawn.

Revision 2's own findings (renamed S1 to S4 so they do not collide with the second review's ids):

- **S1** (sibling job named like the check): closed by test 3, now an allowlist (N6).
- **S2** (a repository secret shadows the organization policy secret): outside the design (N4, Q2).
- **S3** (the App's installation covers the policy repository): `story:api-policy-repository-writes`
  for the verb route; Q3 for the App.
- **S4** (merge-group runs): not counted as proof (test 2).

Second review (revision 2):

- **N1** (tag named like the default branch): closed by the range annotation (story 1) and test 2
  (story 2).
- **N2** (default-branch run reuses a receipt): closed in story 1: no reuse on that run, `reused=false`
  in the annotation, committer and author checks in admission ahead of reuse.
- **N3** (the audit can be muted): closed by the list derived from the policy (story 3) and audit
  freshness (story 2). Notification is a convenience, not the control.
- **N4** (the boundary is wider than C1 and C2): written down as "The boundary"; open question Q4.
- **N5** (`workflow_dispatch` with `inputs.head`): closed in story 1.
- **N6** (test 3 a denylist): test 3 is an allowlist.
- **N7** (read bound wrong): bound corrected to 1 + 2k per candidate; verdict cache (story 2).
- **N8** (how `ci` recognises a default-branch push): `event.ref`, never `head_branch` (story 1).
- **N9** (policy skew): the annotation's policy digest, compared in test 2.
- **C2 today** (`api` has no target guard; the policy repository is writable through it): the new
  story `story:api-policy-repository-writes`.

## Order of work

1. **`story:api-policy-repository-writes`.** `api` and `gh -- api` refuse every write whose decoded
   path names the policy repository (both path forms) and every GraphQL mutation naming it;
   `bot -- push` refuses that destination. The owner answers Q3 and Q4.
2. **`story:ci-committer-pr-bound`, extended.** Committer check in admission; no receipt reuse on the
   default-branch push; the range annotation; a `workflow_dispatch` head equal to `GITHUB_SHA`; the
   default branch identified by `event.ref`. Releasable alone: consumers pin Gates commits, so a
   release changes nothing until a pin moves.
3. **`story:push-range`, extended.** Provenance reads the annotation (N1, N2, N9); every annotated
   default-branch push run on `C` is green; the allowlist shape (N6); audit freshness (N3); the read
   cache (N7). Ships inert, because the list is empty.
4. **`story:history-audit-schedule`**, with the list derived from the policy and the freshness
   annotation story 2 reads.
5. The owner adds the first trusted Gates id, after a green audit, after step 1 has shipped and after
   answering Q3 and Q4.
6. **`story:consumer-pins-trusted`.** Pins move, repository by repository.

The first entry on the trusted list waits for `story:api-policy-repository-writes`; stories 1 and 2
may ship before it only because story 1 does not read the list and story 2 does nothing while the
list is empty.

**For spindle-shaped commits to stop blocking:** the release that carries stories 1 and 2 (the binary
`common.yml` downloads carries story 1, the local hooks carry story 2), then step 5, then that
repository's pin moves (step 6) and its hooks are reinstalled.

## The policy `baseline` afterwards

Set once at enrolment. It is the range's lower end wherever `B` does not qualify, the anchor every
head and `B` must descend from, and the start of `audit --history`. No existing value needs a
migration. No policy edit is part of this design. The trusted list is a new file in the policy
repository, maintained by the owner from story 2 on.

## Rejected alternatives

- **(B) The gate advances the start itself after each verified merge.** It needs a trusted, writable
  record of the moving start, and it still cannot advance past a commit it refuses.
- **(C) No change.** Every GitHub-written commit that the local merge proof cannot prove stops a
  repository until the owner moves its baseline (36 moves since 2026-10-05).
- **(D) Trust `B` because the rulesets exist (revision 1).** The required check is forgeable by the
  App (G1), and the narrowed `ci` ranges made it cover nothing (G2, G3).

## Not verified

Each item, and the check that would settle it:

- **The App's administration write and actions write permissions.** They decide whether the App can
  register a self-hosted runner whose label matches `ubuntu-24.04` (the trusted job would then run on
  a session's machine) and whether it can delete a red workflow run. Check: the owner reads the
  installation's `permissions` with the App JWT or on the App settings page.
- **That GitHub labels a tag push run `head_branch: <default>` for a tag named like the default
  branch.** The design no longer relies on `head_branch`; the answer shapes story 2's test fixture.
  Check: push such a tag in a sandbox repository and read the run.
- **That a `workflow_dispatch` run's check run attaches to the dispatched ref's tip.** Check: dispatch
  a caller on a sandbox branch and read `commits/<tip>/check-runs`.
- **That a `::notice` from the job of a called `common.yml` shows as an annotation on the caller's
  check run `common / Security and privacy`.** Story 2 depends on it. Check: one run of story 1's
  binary in a sandbox caller, then `GET check-runs/<id>/annotations`.
- **Whether `bot -- push` to the policy repository passes today.** Check: the refusal test of
  `story:api-policy-repository-writes` makes it moot for the verb; the App route stays under Q3.
- **That a fork's push runs do not appear in the base repository's `commits/<C>/check-runs`, and that
  `pull_request_target` runs never report `event: push`.** Inferred from GitHub's model. Check: a fork
  pull request in a sandbox repository, then read the check runs on its head.
- **That GitHub notifies the last editor of a `cron` line about a failed scheduled run.** Inferred
  from GitHub's documentation; the design no longer relies on it. Check: a red scheduled run in a
  sandbox repository.
- **That GitHub accepts the ref updates of G1 and G2, and whether commit metadata rules apply to
  API-written commits with any committer email** (first review). Check: writes in a sandbox
  repository with copies of the rulesets.
- **Every code claim of stories 1 and 2 and of `story:api-policy-repository-writes`.** The code is
  not written. Check: their acceptance tests with recorded mutation evidence.

## Open questions for the owner

- **Q2. The bot App and repository-secrets write (C1).** Today the App has no secrets permission
  (403, verified by the second review).
  - (A) The App never gets secrets write. `story:policy-publish-bot-route` (draft PR #54) is closed
    or moved to a separate App whose key no session's `bot` verb can mint.
  - (B) Grant it, and accept that a session can choose the policy the trusted job reads, which
    voids the provenance argument.
  - (C) Read the installation's permissions first, and decide then.
  - Default: A (unchanged from revision 2).
- **Q3. Take the policy repository out of the bot App's installation.** Today the installation covers
  it, its contents are readable and its default branch is unprotected (bot reads, 2026-11-24).
  - (A) Remove it, so only the owner's login writes the policy repository. A token minted with the
    App key can then not write it either.
  - (B) Keep it. The verb guard of `story:api-policy-repository-writes` closes the verb route, and a
    session that mints a token with the App key can still write the policy and the trusted list.
- **Q4 (finding N4). What the boundary is.** The App private key, the receipt signing key, the local
  policy clone and the owner's `gh` login are readable or usable by the sessions' OS user. Options:
  - (A) Write down that sessions never read the key files, never edit the policy clone except through
    the owner, and never use the owner's login; the design then holds for every session that keeps
    that rule, and no code enforces it.
  - (B) Move the keys and the owner's login out of the sessions' reach (another OS user, a signing
    service, a hardware key, a login only the owner unlocks), so the boundary is enforced.
  - (C) Accept the wider boundary as it is, and treat the design as protection against mistakes, not
    against a session acting on purpose.
