---
format: aep.planning-md/3
id: review-result:merge-baseline-security-1
kind: review-result
status: active
title: 'Security review 1: API merge proof and delete-branch defaults'
relations:
- reviews: story:api-merge-push-admitted
- reviews: story:bot-delete-branch-defaults
revision: 1
---
```
unit: the gates merge-baseline / delete-branch defaults wave, 28aa460..9fa978d on review/merge-baseline-security; reviewer commit b42d3d1 (tests only)
verdict: NEEDS-CHANGE
cases: executed 315→322, red 1
origin: introduced 1 / pre-existing 0 / undecided 0
```

Cases added in `tests/security_merge_baseline.rs`: `a_second_ruleset_of_admitted_rule_types_marks_the_branch_protected`
(red at review time: the branch was deleted), `the_bot_authority_rulesets_alone_are_deleted`,
`a_symlinked_hook_configuration_is_refused`, `a_group_writable_hook_directory_is_refused`,
`an_unparsable_hook_configuration_is_refused_not_ignored`,
`a_linked_worktree_resolves_the_common_configuration`,
`the_binary_refuses_an_untrusted_configuration_before_any_credential`.

On "never a protected branch": reading "protected" as classic protection plus rulesets other than
the bot-authority one matches the decision's intent, since GitHub's `protected` flag would refuse
every branch of a repository carrying the bot-authority ruleset; the code enforced that reading
only by rule type until F1 is fixed.

Checked and sound: the `protection.enabled` shape (live, read-only), default branch refused first,
unmerged and moved tips refused before the DELETE, the DELETE path fixed to
`git/refs/heads/<branch>`, the repository resolved and shape-checked before any read and before
any credential, `--policy` not needed, `config.json` read through `protected_read`, and the merge
proof (tests only, covered by existing person-merged and unmerged cases).

Outcome: fixed in fix round 1 (rules are attributed to their rulesets; restricting rules from
one ruleset, each once; an unattributed rule is refused). Remaining, by design: a branch whose only
ruleset is a single non-bot ruleset of restricting types is admitted by the check; without the
bot-authority ruleset the App holds no bypass there, so GitHub itself refuses the deletion.

```findings
- file: src/delivery.rs
  line: 233
  category: integrity
  severity: warning
  verdict: NEEDS-CHANGE
  origin: introduced
  message: "now that top-level `protected` no longer refuses ruleset-covered branches, `rulesets` judges by rule type only, so a second non-bot ruleset made of admitted types (non_fast_forward, update, creation) is admitted and the branch is deleted (red: a_second_ruleset_of_admitted_rule_types_marks_the_branch_protected)"
```
