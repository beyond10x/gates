---
format: aep.planning-md/3
id: review-result:dbc-adversary-1
kind: review-result
status: active
title: 'Adversary pass 1: delete-branch comparison and install defaults'
relations:
- reviews: story:bot-delete-branch-compare
- reviews: story:install-from-installed-config
revision: 1
---
```
unit: the gates delete-branch comparison / install defaults wave, on review/dbc-adversary; reviewer commit 0842147 (tests only)
verdict: NEEDS-CHANGE
cases: executed 336→344, red 2
origin: introduced 1 / pre-existing 0 / undecided 0
```

Cases added in `tests/adversary_dbc.rs`:
`following_the_refusals_remedy_installs_past_an_unparsable_configuration` (red),
`an_explicit_repository_and_policy_install_past_a_configuration_that_is_not_owner_only` (red),
`the_extracted_guard_refuses_everything_the_inline_guard_refused`,
`percent_sequences_in_names_cannot_forge_the_comparison_separator`,
`key_and_scanner_precedence_is_environment_then_installed_then_default`,
`a_symlinked_installed_configuration_is_refused`,
`a_symlinked_policy_named_by_the_installed_configuration_is_refused`,
`a_linked_worktree_reinstalls_from_the_common_configuration`.

Finding F1 (warning, introduced, src/main.rs install): install read the installed configuration
whenever any of repository, policy, key or scanner was unnamed and refused on any problem with it,
so a left-behind unparsable or not-owner-only `config.json` blocked an explicit
`--repository`/`--policy` repair install, and the refusal's own remedy was refused again.

Could not break: `%` is always encoded in names, so `%2E%2E%2E` cannot be forged; a literal `..`
is refused by the guard; the tip is hex-checked; every delete-branch test double applies
`api_path_admitted`; linked worktrees resolve the common configuration.
