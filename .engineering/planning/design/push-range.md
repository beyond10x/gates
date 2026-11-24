---
format: aep.planning-md/3
id: design:push-range
kind: design
status: draft
title: Check only the commits a push adds to the published default branch
summary: Where the range is computed today, the new bound per path, receipt format, threat cases and the condition under which the direction holds
relations:
- designs: story:push-range
revision: 1
---
## Verdict

**Holds, with one condition the picked direction did not state.** The published default branch may
be the lower end of the checked range only where an authenticated read shows that every update of
that branch is held to the common check: the exact `b10x-bot-branch-authority` ruleset **and** an
active ruleset on the default branch, with no bypass actor, that requires `common / Security and
privacy` from GitHub Actions (integration 15368). Without the second ruleset the bot App can move the
default branch through the API to a commit no gate has seen, and the App token is in reach of every
local session (`api` verb). Without the first, anyone with write access can. Where the condition does
not hold the gate keeps today's range from the enrolled baseline, so nothing gets weaker; those
repositories keep today's failure mode until their rulesets are completed (open question Q1).

Read on 2026-11-24 with the owner's read-only API access: 43 public enrolled repositories meet the
condition (spindle among them); 20 public ones have the authority ruleset but no required common
check; 6 have no authority ruleset (beyond10x/ratchet among them); private ones have no rulesets on
their plan.

Two parts of the direction as stated are not true of 0.1.28 and are part of this design:
`b10x-gates audit` reports only findings in the baseline **tree**, not the commits since the
baseline, so it does not yet report history; and `ci` checks a push of the default branch from the
baseline, so the after-the-fact catch for that branch has to move to the push's own range.

## Question

Today every push re-judges every commit from the repository's enrolled baseline to the head. One
commit on the default branch that the gate does not accept blocks every later push of that
repository, and the only repair is a hand edit of the trusted policy that moves the baseline. The
owner picked on 2026-11-24 "A: check only new commits": a push is judged on the commits it adds on
top of the published default branch. This note says exactly where the range is computed today, what
it becomes, how the gate learns the lower end without trusting the candidate, and what each threat
case looks like afterwards.

The case that prompted it: three commits on spindle's `main`, written through the GitHub API as
single-parent commits with the bot as author but not as committer, reached `main` through a pull
request. CI admitted them (it checks the author only). A later push of a new branch was refused by
the pre-push walk with "a commit on the pull request head line is neither the bot's nor a branch
update" (`src/published_merge.rs:764-768`).

## Where the range is computed today (0.1.28, `ba05649`)

| # | path | file:line | what it does with the baseline |
|---|---|---|---|
| 1 | candidate build, used by every path below | `src/git.rs:801-946` (`build`), `:814-822` ancestry check, `:823-832` `rev-list --reverse --topo-order <baseline>..<head>`, `:856-859` author admission per commit, `:931-940` `Binding.baseline` | builds the units to scan and the receipt binding from every commit after the baseline |
| 2 | local `check`, `verify`, `publish` | `src/main.rs:676-677` (`git.candidate`), `:52` (doc: "all new commits since the trusted adoption baseline") | candidate from #1 |
| 3 | `publish` ancestry proof | `src/main.rs:732-740` → `src/delivery.rs:52-61` (`verify_publication`) → `src/published_merge.rs:54-95` (`verify`: `:66-72` ancestry, `:73-78` `rev-list <baseline>..<head>`, `:79-93` each non-bot commit proved as a GitHub merge on the published default branch) | walks every commit after the baseline |
| 4 | pre-push hook, and so `bot -- push` and `publish --remote-ref` | `src/hooks.rs:264-307`: `:279` candidate from #1, `:280-286` `verify_pre_push` → #3 with `PushEvidence` (`src/delivery.rs:63-78`, API read only when a non-bot commit is met) | both walks per pushed ref |
| 5 | ancestor receipt reuse | `src/evidence.rs:215-226` (an ancestor receipt's head must lie in the candidate's range), `:230` `candidate_from` → `src/git.rs:791-799` → #1 with the same baseline | rebuilds the ancestor's candidate from the baseline |
| 6 | receipt statement and verification | `src/evidence.rs:17` (`DOMAIN` `receipt/1`), `:39-41` public digest token `all-outgoing`, `:92-96` (statement: "every commit from the baseline to its head"), `:107` `version: 1`, `:120-133` exact `Binding` equality, `:135-145` currency, `:176-185` reuse doc | binds `baseline` and the exact `commits` list |
| 7 | `ci` verifier | `src/delivery.rs:942-1082`: `:976-982` merge group "scan runs from the policy baseline, `base_sha` decides nothing", `:1029` fetch refspecs `<head> <baseline>`, `:1080` candidate from #1; `src/main.rs:571-591` receipt lookup and scan | from the baseline for every event |
| 8 | `audit` | `src/main.rs:86`, `:658-666` → `src/git.rs:982-991` (`historical`: the baseline tree only) | reports the baseline tree, not the commits after it |
| 9 | documentation | `README.md:19` (receipt "still states that every commit since the baseline passed"), `:23` (pre-push inspects "every commit since the trusted adoption baseline"; merge proof), `:49` (baseline and `audit`), `:57` (CI verifies the "adoption baseline"), `:83` ("Every commit after the trusted adoption baseline must have the exact raw Git author") | |

`ess/domains/evidence.yaml` already models the receipt with a field `base`; it needs no change.

## The new range

Notation: `rev-list <head> --not <B>` is every commit reachable from the head and not from `B`, side
branches included. `B` is the **bound**: one exact commit.

### Which object decides "already on the default branch"

`B` is the commit GitHub reports as the tip of the default branch, read through an authenticated
call, at the time of the check:

- `GET /repos/<repo>` (numeric id equal to the policy's, `default_branch`, visibility), the ruleset
  list and the two rulesets named below, and `GET /repos/<repo>/git/ref/heads/<default>`. This is
  `Authority::load` (`src/published_merge.rs:286-338`) plus one new check. Locally the reads use the
  App token (`PushEvidence` in the hook, `Github::bot()` elsewhere).
- GitHub controls the answer. Who can move the branch is decided by the rulesets: only the App
  (authority ruleset), only with a successful `common / Security and privacy` run from GitHub
  Actions on the new tip (required-check ruleset without bypass). So every commit on the branch has
  passed `ci` over a range that contained it, or was already there before the ruleset held.
- A local remote-tracking ref (`refs/remotes/origin/main`) is **never** used: any local process can
  set it to the candidate head and exempt everything. The bound object must already be in the local
  store; when it is not, the push refuses with a line naming the commit and telling the caller to
  fetch through the bot. Nothing is fetched implicitly.
- The bound is used only when all of these hold; otherwise `B` is the enrolled baseline and the path
  behaves exactly as today:
  1. visibility public and the exact authority ruleset (`verify_branch_authority`, unchanged);
  2. a ruleset listed for the repository with `enforcement: active`, `target: branch`, a
     `ref_name` condition that includes `refs/heads/<default>`, `~DEFAULT_BRANCH` or `~ALL` and does
     not exclude it, `bypass_actors: []`, and a `required_status_checks` rule with an entry
     `{context: "common / Security and privacy", integration_id: 15368}`; a listed ruleset that
     cannot be read refuses, as the authority read does;
  3. the default ref answers with a commit; a 404 or GitHub's empty-repository 409 means no
     published head, so `B` is the baseline; any other failure refuses;
  4. `B` descends from the baseline (`merge-base --is-ancestor <baseline> <B>`); otherwise refuse
     with "published default branch does not descend from the enrolled baseline", which is how a
     rewrite of the default branch past the baseline still stops every push.

The head must still descend from the baseline, as today (`src/git.rs:814-822`), so an orphan line is
still refused.

### Per path

| path | today | new |
|---|---|---|
| pre-push hook (`bot -- push`, `publish --remote-ref`) | `<baseline>..<head>` per ref, twice (#1, #3) | `B` read **once per hook run** with `PushEvidence`; per pushed ref `rev-list <head> --not <B>`. Every commit in it must pass `verify_bot` (exact bot author and committer); the first that does not refuses with `commit <oid> is not on the published default branch and is not the bot's own commit`. With `B` = baseline, today's walk with its merge proofs runs unchanged. The scan and receipt use the same range |
| `publish` | candidate and `verify_publication` from the baseline | the same bound function with `Github::bot()`; the receipt must bind the same `B`, else "receipt repository or exact range mismatch" as today, and the caller re-runs `check` |
| `check`, `verify` | from the baseline, offline | the same bound with `Github::bot()` when the App credential is readable; without it `B` = baseline and the output line says `bound=baseline`. A receipt binds its bound, so a mixed pair never matches by accident |
| ancestor receipt reuse | rebuilds the ancestor candidate from the baseline | rebuilds it with the **receipt's own** `base` (`candidate_from(.., base, ..)`), verifies it in full, and counts its commits as covered; every other commit of the new range is scanned. Sound whatever the two bounds are, because coverage is by commit id |
| `ci`, `pull_request(_target)` | `<baseline>..<head>` | `rev-list <head> --not <pull_request.base.sha>` |
| `ci`, `merge_group` | from the baseline | `--not <merge_group.base_sha>` |
| `ci`, push of the default branch | from the baseline | `--not <before>`; when `before` is all zeros, or cannot be fetched (a force push made it unreachable), the baseline |
| `ci`, push of another branch, a tag, `workflow_dispatch` | from the baseline | `--not <D>`, where `D` is `refs/heads/<repository.default_branch>` fetched by name from the repository URL in the same fetch; no `D`, the baseline |
| `audit` | baseline tree only | unchanged, plus `--history`: every commit in `rev-list <B> --not <baseline>` with `B` read as above, its authorship verdict and its findings, written to the protected report; it never refuses |

`ci` takes its bound from the event and from GitHub, not from a ruleset read: it **is** the required
check that makes the default branch trustworthy, so it judges what the event adds. The event is
trusted workflow input (`src/delivery.rs:932`); every bound is fetched by id into the fresh bare
store beside the head and the baseline (refspecs at `:1029`); a bound that cannot be fetched falls
back to the baseline, which checks more, never less.

### Edge cases

- **First push of a repository**: no published head (404/409), so `B` = baseline: today's range.
- **Push to the default branch itself**: `B` is the current remote tip, so the range is exactly the
  commits the push adds. A non-fast-forward push is refused by the bot and by the ruleset.
- **Tag**: tag on commit `C`; range `rev-list C --not B`, normally empty for a tag cut from the
  default branch; the `tag-ref` and every tag object are scanned as today (`src/git.rs:882-924`).
- **Branch whose base is behind the default branch**: the range is the branch's own commits since
  it forked; nothing of the default branch is re-judged. If the branch merges the default branch in
  (bot `merge`), that merge commit is in range and its units are its diff against its **first**
  parent (`src/git.rs:860-870`), so content the default branch holds is scanned again inside that
  merge, and a finding there refuses as today. Cutting the branch afresh from the default branch
  avoids it. Not changed here.
- **A commit removed from the default branch** (a purge by force push) is no longer under `B`, so a
  branch that still carries it is judged again in full. The bound is read on every push, never cached.

## Receipts and evidence

The format changes:

- `Binding` gains `base: String`, the exact commit the range excludes (the baseline on the fallback
  path). `baseline` stays. `Payload.version` becomes 2, `DOMAIN` `b10x.gates.receipt/2`, and the
  public digest token `all-outgoing` becomes `pushed-range-1`.
- Statement: "the common checks passed for every commit reachable from `head` and not from `base`,
  and `base` descends from `baseline`".
- Receipts made by 0.1.28 fail `current` (version and Gates version), so they are ignored and the
  range is scanned. Under the new range that is a small scan. No receipt is converted.
- A consumer whose `.github/workflows/common.yml` pin downloads an older binary (the caller pins a
  Gates commit; that commit's `common.yml` pins a release) does not parse a version 2 receipt
  (`deny_unknown_fields`; `receipts` skips it, `src/delivery.rs:907-929`) and scans from the
  baseline as today. Its CI keeps today's range and today's failure mode until the pin moves. For
  the spindle case that is enough: CI admitted those commits already; only the local walk refused.
- Installed hooks are hardlinks to one binary; each repository needs `install` again after the
  upgrade (`README.md:21`).

## Threat cases

| case | caught before | caught after | where, after |
|---|---|---|---|
| a commit written to the default branch through the API | yes on a qualifying repository: the required-check ruleset has no bypass, so the ref update needs a successful Actions run of the common check on that tip; the identity ruleset needs the bot's email as author and committer | yes | `ci` on the push of the default branch (`--not <before>`); `audit --history`. No longer at every later local push |
| a commit with a person as author reaching the default branch | yes: the identity ruleset (author email, every branch, no bypass); `ci` on the pull request (author check over `--not <base.sha>`) | yes | `ci` on the push of the default branch; `audit --history` |
| a secret in a commit already on the default branch | it was scanned when it was added (pull request `ci`, pre-push) under the rules then in force | yes | `ci` on that push; `audit --history`; GitHub secret scanning. The content is public from the moment it landed under either design; a later push no longer refuses. A commit that brings the same line into a new branch through a merge is still refused (edge case above). The repair is rotation and, if wanted, a purge, never a baseline move |
| a force push of the default branch | the authority ruleset lets only the App, and the bot refuses force pushes; the required check still applies to the new tip | yes | `ci` on that push (`--not <before>`); a rewrite past the baseline refuses every gated push (bound rule 4); a purged commit is judged again in any branch that still carries it |
| a pull request head line with an unacceptable commit not yet on the default branch | **refused**: it is in `rev-list <head> --not <B>`; pre-push refuses naming the commit; `ci` refuses it on the pull request | n/a | |
| a side branch merged into the candidate | its commits not on `B` are in the range (all parents are walked) and must be the bot's and pass the scan; its commits already on `B` are skipped | n/a | |
| a repository without the bot rulesets (beyond10x/ratchet) | as today: the bound condition fails, `B` = baseline, today's walk and scan | as today | as today: the next gated push refuses |
| a policy change adding a rule | applies to new commits | yes | `audit --history`; history on the default branch is no longer re-judged at each push |

What the change gives up, stated once: the gate no longer re-proves, at each push, that history on a
qualifying default branch is acceptable. That proof never prevented a publication (the content was
public when it landed); it turned every such commit into a stop for the whole repository. The
rulesets carry the "who can write" part, `ci` carries the content part before the merge and again on
the default-branch push, and `audit --history` is the report. A ruleset read proves the rule holds
now, not that it held when each commit landed; `audit --history` covers that gap.

## The policy `baseline` afterwards

It stays an exact trusted commit, set once at enrolment, and means:

1. the lower end of the range where the bound condition does not hold (no rulesets, private, empty
   remote, a bound that cannot be fetched in `ci`);
2. the anchor every head and every bound must descend from;
3. the start of `audit --history` and the tree `audit` reports.

No existing value needs a migration: every current baseline is an ancestor of its default branch,
or that repository's pushes are refused today already. The 36 moves since 2026-10-05 stay as they
are. No policy edit is part of this design.

## Failing tests first

One line each; the fake API is the `Evidence` map in `tests/published_merge.rs`, with a second
ruleset (required check) added for the qualifying cases. Every guard test also gets mutation
evidence.

1. Spindle shape: `B` holds three single-parent commits with the bot as author and GitHub as
   committer; a new bot commit on top is admitted by pre-push and `publish` (today: refused).
2. `B` holds a commit with a person as author; a new bot branch on top is admitted, and the
   candidate holds only the new commit's units.
3. `B` holds a commit with a secret finding; a new branch is scanned over exactly the new commit's
   units (counting scanner).
4. A commit on the candidate's own line with a person as author, not on `B`, refuses; the line names
   its id.
5. Same with a single-parent GitHub-committed commit not on `B`; refuses naming it.
6. A bot merge of a side branch holding an unacceptable commit not on `B` refuses naming that commit.
7. `refs/remotes/origin/main` set to the candidate head changes nothing: case 4 still refuses.
8. Each failed bound condition selects the baseline, one case each: no required-check ruleset;
   a bypass actor on it; `integration_id` other than 15368 or missing; another context; enforcement
   `evaluate`; the default branch excluded; a private repository. Each keeps today's refusal of
   case 1.
9. Default ref 404 and 409 select the baseline; a 500 after retries refuses.
10. `B` not in the local store refuses with a line naming `B`, before any scan.
11. `B` not descending from the baseline refuses.
12. Receipt: `base` is bound; a receipt for another `base` does not verify; a version 1 receipt does
    not verify; a version 2 payload signed under the version 1 domain does not verify.
13. Ancestor reuse where the retained receipt has an older `base` scans exactly the commits it does
    not cover.
14. `ci` (`tests/ci_policy.rs` fixture): pull request uses `base.sha`; merge group `base_sha`;
    default-branch push uses `before`; zero or unfetchable `before` uses the baseline; branch, tag
    and dispatch use the fetched default ref.
15. A tag on a commit of `B`: only tag units are scanned.
16. `audit --history` reports a finding and an inadmissible author on `B` and exits 0.

Existing tests in `tests/published_merge.rs` keep their meaning: their fixtures have no required-check
ruleset, so they run the fallback path.

## Smallest set of code changes

1. `src/published_merge.rs`: `pub enum Bound { Published(String), Baseline }` and
   `pub fn bound(git, policy, repository, api) -> Result<Bound>` from `Authority::load` plus the
   required-check ruleset check; `verify` takes the bound and, on `Published`, requires
   `verify_bot` for every commit of `rev-list <head> --not <B>`.
2. `src/git.rs`: `build`, `candidate`, `candidate_from` take the bound commit; `rev-list <head>
   --not <base>`; `Binding.base`; the ancestry checks of rule 4.
3. `src/hooks.rs`: read the bound once before the ref loop; pass it to both.
4. `src/main.rs`: `check`/`verify`/`publish` compute the bound; `audit --history`.
5. `src/evidence.rs`: version 2, domain, digest token; `check_reusing` rebuilds with the receipt's
   `base`.
6. `src/delivery.rs`: event bound selection, fetch of the bound, baseline fallback; `PushEvidence`
   comment (the read is no longer lazy).
7. `README.md` lines 19, 23, 49, 57, 83; `CHANGELOG.md`.

## Rejected alternatives

- **(B) The gate advances the start itself after each verified merge.** It needs a trusted, writable
  record of the moving start (the policy is the owner's, a local file is candidate-controlled), which
  rebuilds the default branch as a second ledger; and it still cannot advance past a commit it
  refuses, so the stop remains.
- **(C) No change.** Every commit on a default branch that the gate does not accept stops all pushes
  until the owner edits the trusted policy (36 baseline moves since 2026-10-05), and the edit
  re-judges nothing that `audit` could not report without stopping anyone.

## Open questions for the owner

- **Q1. Repositories whose default branch lacks one of the two rulesets** (20 public with the
  authority ruleset but no required common check, 6 without the authority ruleset, every private
  one). (A) keep today's range from the baseline there; (B) use the published head there too,
  accepting that nothing proves its commits passed the gate; (C) A, and the owner adds the missing
  required-check rulesets (ruleset changes are the owner's). Default: A.
