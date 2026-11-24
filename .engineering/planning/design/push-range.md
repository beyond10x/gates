---
format: aep.planning-md/3
id: design:push-range
kind: design
status: draft
title: Check only the commits a push adds to the published default branch
summary: 'Revision 2: trust a default-branch commit only by the provenance of its check run; ci committer check and default-branch bound; scheduled history audit; consumer pins; every adversary finding dispositioned'
relations:
- designs: story:push-range
- designs: story:ci-committer-pr-bound
- designs: story:history-audit-schedule
- designs: story:consumer-pins-trusted
revision: 3
---
## Verdict (revision 2)

**Holds, under two conditions that the gate's code cannot enforce (C1, C2).** Revision 1 trusted the
published default branch because two rulesets exist. That was wrong, and the adversary review
showed why (G1 to G7 below). Revision 2 trusts a default-branch commit `B` only through the
**provenance of the check run on `B`**:

- the run is the canonical shared-gates caller, on a push of the default branch;
- the caller calls a Gates `common.yml` commit on a trusted list;
- that binary checked `baseline..B`, committers included, and found it clean.

Every other case uses the enrolled baseline range, exactly as 0.1.28 does.

What revision 2 changes for a repository that qualifies:

- **Removed:** the class "a GitHub-written commit on the default branch that the local merge proof
  cannot prove", which is spindle's case.
- **Not removed:** content and authorship problems already on the default branch. They keep the
  default branch's check red, so the repository falls back and stays stopped. That is the honest
  state. It is repaired with exact policy exceptions, never by moving a baseline.

Conditions (each outside the gate's code; open questions Q2 and Q3):

- **C1.** No session can choose the policy the trusted `common.yml` job reads. The canonical caller
  maps `secrets.B10X_GATES_POLICY(_GZ)` by name, but a **repository** secret of that name shadows the
  organization secret. So the bot App must not hold repository-secrets write. Not verified: reading
  the installation's permissions needs the App JWT. The draft story
  `story:policy-publish-bot-route` (draft PR #54) would grant exactly that permission.
- **C2.** The trusted list is read from the local clone of the policy repository. The bot App's
  installation includes that repository (verified 2026-11-24 with a bot GET of
  `/installation/repositories`: 86 repositories, the policy repository among them). So any session
  can write the policy repository through `api`, today, for `policy.json` as much as for the new
  list. Revision 2 adds no new exposure, but the list is only as safe as the policy file.

The owner decided Q1 on 2026-11-24: **A**. A repository that does not qualify keeps the baseline
range.

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

## The trusted bound `B` (local paths)

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

### Provenance of the check on `B` (G1, G5)

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
2. Among those runs, the newest one with `event: push`, `head_branch` equal to the default branch
   and `head_sha == C` concluded `success`, and so did its workflow run. On spindle's `main` tip,
   read 2026-11-24, this passes: one push run on `main` and one on tag `0.19.1`, both
   `shared-gates.yml`, both `common.yml@95d64e3…`.
   - Tag runs are only held to test 1. Their range is not the baseline range.
   - `merge_group` runs are only held to test 1, for the same reason. This deviates from the
     brief: a merge-group run bounded by the default branch covers only what the group adds, and
     counting it would reopen G3. The queue's merge triggers a push run on the default branch
     anyway.
   - A tag named like the default branch fails the candidate. `head_branch` cannot tell the two
     apart.
3. `.github/workflows/shared-gates.yml` at `C` has the canonical shape. It is read locally as a blob
   and parsed as data, never run:
   - `jobs` holds exactly one job, `common`;
   - that job has exactly the trusted `uses:` ref;
   - it has a `secrets:` map whose only keys are `B10X_GATES_POLICY_GZ` and/or `B10X_GATES_POLICY`,
     each with the value `${{ secrets.<same name> }}`;
   - it has no `with:`, `if:` or `name:`.

   This closes the variant the review did not list: a caller that calls the trusted `common.yml`
   under another job id, so the real check fails under another name, and adds a plain job named
   `common / Security and privacy` that runs `true`. Every caller seen on 2026-11-24 has this shape
   (43 of 43, `adv-out/callers/`).
4. `C` descends from the baseline. Otherwise the candidate fails, and with it every older one (R6).

**Fetch.** `B` is fetched **by id** through the bot remote when it is not in the local store. No ref
is written and none is trusted. A failed fetch selects the baseline (R2).

**Any read failure selects the baseline (R1).** This includes 404/409 on the default ref, 403 on a
private repository, a 5xx after retries, and a page that does not parse. A wider range is never
weaker, so a refusal here would add noise and no safety. The baseline is also selected when the
trusted list is missing or empty, and when no App credential is readable (`check` and `verify`
offline).

**What a session sees when its repository does not qualify:** one line, then today's walk.

```
b10x-gates: bound=baseline for <owner>/<repo>: <reason>
```

The reasons:

- `the check on <C10> ran common.yml@<sha10>, not a trusted Gates workflow; move the pin in .github/workflows/shared-gates.yml to <newest trusted sha>`
- `no successful push run of shared-gates.yml on the last 20 commits of <default>`
- `shared-gates.yml at <C10> is not the canonical caller`
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
  both checks story 1 delivers: the committer admission (G4), and the push run of the default branch
  on the baseline range (G3).
- **At a release.**
  1. The release commit that moves `common.yml` to the new binary is merged.
  2. The owner adds that commit id to the list in the policy repository, as a policy-repository
     commit. A session prepares the line; the owner commits it.
  3. Ids stay on the list until the owner removes one, for example after a rule fix that the old
     binary lacks.
  4. The release procedure in `README.md` (Development and releases) gains this step.
- **Switch.** The list stays empty, so no repository qualifies, until the scheduled audit
  (story 3) has run green once.

## The range per path

| path | revision 2 |
|---|---|
| pre-push, `publish`, `check`, `verify` | `rev-list <head> --not <B>`, walked with **today's** proof: a commit not by the bot must be a proved GitHub merge on the published tip `T`, otherwise it is refused, naming it. A commit in the range is either new (and must be the bot's) or lies between `B` and `T` (and is proved as today). The head must descend from the baseline, as today. With `B` = baseline, this is exactly 0.1.28 |
| ancestor receipt reuse | rebuild the ancestor's candidate with the receipt's own `base`, verify it, count its commits as covered |
| `ci`, push of the default branch | **the baseline range, as today** (G3). Only a run of this kind proves `B` |
| `ci`, pull request, merge group, tag, other branch, dispatch | `rev-list <head> --not <D>`, where `D` is `refs/heads/<repository.default_branch>` fetched by name from the repository URL in the run, **never** `pull_request.base.sha` or `merge_group.base_sha` (G2). If there is no `D` or the fetch fails: the baseline |
| `ci`, every event | committer admitted only as exactly `b10x-bot[bot] <316511680+b10x-bot[bot]@users.noreply.github.com>` or exactly `GitHub <noreply@github.com>`, with name and email both exact (G4); author as today |
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
- **Acceptance rule, everywhere (R3, R4):** a receipt for the same head and tags is accepted when its
  `base` is an ancestor of the path's bound and descends from the baseline. It is verified in full
  against the candidate rebuilt with **its own** `base`. Its range is then a superset of the path's.
  - `publish` after a merge into the default branch therefore keeps the receipt from `check`.
  - `ci` on a pull request accepts a local receipt whose `base` is behind `D`.
  - On the default-branch push (bound = baseline), only `base == baseline` qualifies.
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
  hit.
- An author outside the automation identities keeps today's hard refusal. None was found, and the
  identity ruleset's author pattern stops new ones.

## Threat cases (revision 2)

| case | caught before | caught after | where, after |
|---|---|---|---|
| A commit X written through the API onto the default branch, with a forged required check (G1) | No. The App can fast-forward the branch once a check with the right name and integration is green. | Yes | X's tip fails provenance (other path, untrusted pin, non-canonical caller, or a real run that is red because it covers `baseline..X`), so the repository falls back. The next local push refuses X, as in 0.1.28. The scheduled audit turns red. |
| Stacked pull request carrying X (G2) | Yes. X is in `F --not D` and refused on the pull request. | n/a | |
| A person as author reaching the default branch | Partly. The identity ruleset's author email pattern, and `ci` on the pull request, stop it. | Yes | The default-branch push run (baseline range) turns red, the repository falls back, and the scheduled audit turns red. |
| A forged committer name with the bot email (G4) | Yes on trusted pins (committer admission). No on old pins. | Yes | An old pin does not qualify, so today's walk refuses it at the next push. |
| A secret, or a newly added rule, matching history on the default branch | It was scanned when added, under the rules then in force. | Yes | The default-branch push run or the scheduled audit turns red, and the repository falls back. Repair: rotation and an exact exception. No baseline move. |
| A force push of the default branch | Only the bot verb refuses it. The authority ruleset's `non_fast_forward` rule has the App bypass, and `api` does not guard `PATCH /git/refs … force` (correcting revision 1). | Yes | The new tip needs its own green baseline-range push run. A rewrite past the baseline falls back (R6). A purged commit is not under `B`, so it is judged again. Race window: see G7. |
| A pull request head line with an unacceptable commit not on the default branch | **Refused** locally and in `ci`, naming the commit | n/a | |
| A side branch merged into the candidate | Its commits not under `B` are in range and walked | n/a | |
| A repository without the rulesets, private, or on an old pin | As today (Q1 = A) | As today | |
| A session feeding the trusted job its own policy | Closed for a literal value (canonical caller). Open if a session can write a repository secret (C1). | | |
| A session editing the trusted list | Open as for `policy.json` today (C2) | | |

**Window (G7).** Between the hook's read of `T` and the push, a rewind that purges commit Y from the
default branch would let a branch carrying Y be judged with the old `B`. The second read of `T`
after the walk narrows this to the time between that read and the push itself, usually under a
second. It needs an App force push in the same moment. Accepted.

## Findings of the adversary review, with dispositions

- **G1** (forgeable required check): closed by "Provenance of the check on `B`" tests 1 to 3, with G3.
  The variant through a sibling job is closed by test 3. The variant through a policy secret stays
  under C1.
- **G2** (pull-request range by `base.sha`): closed by "The range per path" (`ci` bound `D`, never
  `base.sha`), including stacked pull requests and a base change.
- **G3** (default-branch `ci` narrowed): closed. The default-branch push keeps the baseline range,
  and only that run proves `B`.
- **G4** (committer never checked; the identity ruleset's guarantee overstated): closed by `ci`
  committer admission and the exception route. History count: "G4 on existing history". The threat
  table is corrected.
- **G5** ("passed the check" depends on the pin): closed by the trusted list. Only commits whose
  binary has story 1's checks are listed, and an old pin falls back with a line naming the pin.
- **G6** (catch-after is not a report): closed by story 3, a scheduled `audit --history` that exits
  non-zero.
- **G7** (rewind race): accepted and documented ("Window"). The second read of `T` narrows it.
- **R1** (every push needs the API; a read failure refused): closed. Any read failure selects the
  baseline.
- **R2** (`B` must be local): closed. `B` is fetched by id; a failed fetch selects the baseline.
- **R3** (`publish` after the default branch moved): closed by the acceptance rule (`base` an
  ancestor of the bound).
- **R4** (`ci` receipt reuse rarely matches): closed by the same rule.
- **R5** (many ruleset reads, pattern matching by hand): closed by `rules/branches/<default>` and
  reading only the rulesets it names.
- **R6** (rule 4 refused every push): closed. A rewritten default branch selects the baseline.
- **O1** (absent `bypass_actors`): closed. An absent field does not qualify; test in story 2.
- **O2** (rulesets prove only "now"): accepted. Provenance is read per commit, so a commit that
  landed while a ruleset was off still needs a green trusted baseline-range run. The scheduled audit
  reports what the window let through.
- **O3** (literal `refs/heads/main`): closed by `rules/branches/<default>`. A rename falls back
  loudly.
- **O4** (main moves between reads): closed by the acceptance rule and ancestor reuse.
- **O5** (hook credential): no change needed (verified by the review).
- **O6** (missing tests): closed by the acceptance of stories 1 and 2.
- **False claim, identity ruleset needs bot committer:** corrected in the threat table.
- **False claim, every commit on the branch passed `ci`:** withdrawn; replaced by the provenance
  rule.
- **False claim, ruleset refuses non-fast-forward:** corrected in the threat table.

New in revision 2, from this revision's own reading:

- **N1** (sibling job named like the check): closed by test 3.
- **N2** (repository secret shadows the organization policy secret): condition C1, question Q2.
- **N3** (the App's installation covers the policy repository): condition C2, question Q3.
- **N4** (merge-group runs): not counted as proof (deviation stated in test 2).

## Delivery order

1. **`story:ci-committer-pr-bound`.** `ci` admits committers exactly. `ci` bounds everything but the
   default-branch push by `D`. The default-branch push keeps the baseline range. Ships alone: it
   only adds refusals to `ci` and narrows pull-request scans.
2. **`story:push-range`.** Provenance-trusted `B`, the trusted list file, the local range, receipts
   version 2 with the ancestor-base rule. Ships alone: with an empty list, every repository keeps
   0.1.28 behaviour plus the one-line reason.
3. **`story:history-audit-schedule`.** `audit --history` and a scheduled run in this repository. Its
   first green run is the condition for the first entry on the trusted list.
4. **`story:consumer-pins-trusted`.** Move every qualifying consumer's `shared-gates.yml` to the
   trusted Gates commit, in canonical shape (37 of 43 run 0.1.3 to 0.1.24; 6 run 0.1.26).

**For spindle-shaped commits to stop blocking:**

- Release 0.1.29 needs **stories 1 and 2**. The binary that `common.yml` downloads must carry story
  1, and the local hooks must carry story 2.
- Then the Gates commit that moves `common.yml` to 0.1.29 goes on the trusted list (owner).
- Then that repository's pin moves (story 4), and its hooks are reinstalled.
- Story 3 is not code that 0.1.29 needs, but its first green run is the switch for the list.

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

## Open questions for the owner

- **Q2. The bot App and repository-secrets write (C1).**
  - (A) The App never gets secrets write. `story:policy-publish-bot-route` (draft PR #54) is closed
    or moved to a separate App whose key no session's `bot` verb can mint.
  - (B) Grant it, and accept that a session can choose the policy the trusted job reads, which
    voids the provenance argument.
  - (C) Read the installation's permissions first, and decide then.
  - Default: A.
- **Q3. The App's installation covers the policy repository (C2; pre-existing).**
  - (A) Remove the policy repository from the installation, so only the owner's login writes it.
  - (B) Keep it, and accept that any session can change the policy and the trusted list through
    `api`.
  - Default: A.
