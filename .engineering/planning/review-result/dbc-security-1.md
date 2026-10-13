---
format: aep.planning-md/3
id: review-result:dbc-security-1
kind: review-result
status: active
title: 'Security review 1: delete-branch comparison and install defaults'
relations:
- reviews: story:bot-delete-branch-compare
- reviews: story:install-from-installed-config
revision: 1
---
```
unit: the gates delete-branch comparison / install defaults wave, on review/dbc-security; reviewer commit 638f814 (tests only)
verdict: NEEDS-CHANGE
cases: security_dbc 7, red 1
origin: introduced 1 / pre-existing 0 / undecided 0
```

Cases added in `tests/security_dbc.rs`: `every_delete_branch_refusal_sends_no_delete`,
`the_comparison_path_is_the_tip_and_the_encoded_default_branch`,
`the_extracted_guard_refuses_exactly_what_the_inline_guard_refused`,
`install_refuses_a_symlinked_installed_configuration`,
`install_refuses_a_configuration_in_a_directory_others_can_write`,
`install_key_and_scanner_environment_win_over_the_installed_configuration`,
`install_takes_nothing_from_a_configuration_naming_another_repository` (red).

Finding F1 (warning, introduced, src/main.rs install): with an explicit `--repository` and no
policy, install took the policy, key and scanner from an installed configuration naming another
repository whenever `core.hooksPath` did not point at it; the reused policy still had to enrol
the repository, so a contract gap, not a trust escalation.

Checked and sound: `api_path_admitted` is the old inline guard byte for byte; no DELETE on any
refusal path, an unreadable comparison included; the configuration is read through
`protected_read` (regular file, no symlink, owner, mode, parent directory); flag > env >
installed > default; enrolment checked in `main` and in `hooks::install`; spec matches the code
apart from F1.
