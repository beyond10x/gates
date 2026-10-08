---
format: aep.planning-md/3
id: design:bot-verbs
kind: design
status: in_review
title: Which Git verbs the delivery bot could add
summary: Proposes merge and revert, a guarded delete-branch, and no rebase, cherry-pick or pull, with the security argument for each.
relations:
- informed_by: story:bot-supported-routes
revision: 2
transitions:
- {from: "draft", to: "in_review", at: "2026-10-08T09:43:21Z", actor: "human:timo", revision: 2}
---
## Question

`b10x-gates bot` runs four Git verbs: `commit`, `tag`, `push` and `fetch`. Agents delivering
through it hit the wall with `merge` (six times on 2026-10-08), `rebase` (once; the rewritten
commits were then refused at push) and `push --delete` (once; a remote branch was left behind).
`story:bot-supported-routes` makes those refusals print the route that works today. This note
proposes which verbs the bot could add, and argues each on security grounds. It decides nothing:
each row needs an owner's yes before a story is written.

## What any new verb must keep

1. **Identity.** Every commit the verb creates is authored and committed by the exact bot
   identity, so the pre-push direct-commit check keeps admitting it without a published-merge
   proof.
2. **Scan coverage.** Pre-push already scans every commit from the adoption baseline to the pushed
   head, so a verb that only creates local commits adds no unscanned path to the remote. A verb
   that changes the remote without pushing a commit (a deletion) is not covered by that scan and
   needs its own argument.
3. **No hook bypass, no injected configuration.** The existing `--no-verify`, `-n`, `-c`,
   `--config-env` and `--exec` refusals extend to every new verb, and the verb runs with the same
   `GIT_CONFIG_GLOBAL=/dev/null` environment.
4. **No history rewrite on the remote.** Force-push stays out of reach, so no verb may make one
   necessary for a branch that has already been pushed.
5. **Candidate code stays data.** Repository-local configuration can name merge drivers and
   filters; a verb that would run them must say so.

## Proposals

| verb | proposal | security argument | risk left |
|---|---|---|---|
| `merge` | **add**, as `git merge --no-ff --no-commit <rev>` followed by the bot's own commit, so the merge commit passes `pre-commit` and `commit-msg` like any bot commit. Refuse `-s`/`--strategy`, `-X`, `--squash`, `--ff-only`, `--allow-unrelated-histories` | Today's workaround is the same two commands, so the verb adds nothing an agent cannot already do; it removes the identity mismatch (a plain `git merge` commits as the user, because `pre-merge-commit` is not one of the coordinated hooks, and the push then refuses it). Merged-in commits that are not the bot's still need their published-merge proof at pre-push | A repository-local `merge.<driver>` from `.gitattributes` runs during the merge. The bot already runs `commit` in the same checkout, which can run local filters, so this is no new class; the verb should still pass `-c merge.renormalize=false` and refuse when `.git/config` names a merge driver |
| `revert` | **add**, always with `--no-commit` then the bot commit, same refusals as `merge` | Creates one ordinary bot commit whose content the pre-commit scan reads; it is the rollback path a release needs and today requires two commands | None beyond `commit` |
| remote branch delete | **add as `bot -- delete-branch <branch>`**, never as `push --delete`: resolve the remote tip, require it to be an ancestor of the remote default branch, refuse the default branch, any protected branch and any tag, then delete through the REST API with the App token | A deletion pushes no commit, so the pre-push scan never sees it; the argument has to be the guard itself. Requiring the tip to be merged means no commit becomes unreachable on the remote, so nothing is lost that the default branch does not hold. The API call records the App as the actor | A branch that holds unmerged work of another session cannot be deleted this way; that is the intent. Today's `api --method DELETE` route has no such guard and stays the only route for an unmerged branch |
| `rebase` | **do not add now**. If added later: only onto a remote-tracking ref, only when no commit being rewritten is reachable from any remote-tracking ref, and only when every rewritten commit is already the bot's | Rewriting local, never-pushed bot commits is harmless: the push scans the result. Rewriting pushed commits makes a force-push necessary, which rule 4 forbids; the guard has to prove "never pushed" from local refs that can be stale after a missed fetch | A stale remote-tracking ref turns "never pushed" into a guess. The merge route covers the need without that guess |
| `cherry-pick` | **do not add**; `merge` or `revert` covers the cases seen | Copies a commit's content under a new identity; the content is scanned again at commit, so the risk is provenance (a non-bot change re-issued as the bot's) rather than secrets | The provenance laundering above |
| `pull` | **do not add**; it is `fetch` plus `merge`, and both are or would be verbs | Two verbs with separate refusals are easier to audit than one that combines them | None |
| force push, tag deletion, `reset` of a remote ref | **never** | Each rewrites or removes published history, which the organization does not do | n/a |

## Recommendation

Add `merge` and `revert` first: both reduce to the bot's existing `commit` and close six of the
eight refusals seen. Add `delete-branch` with the merged-tip guard second. Leave `rebase`,
`cherry-pick` and `pull` out.
