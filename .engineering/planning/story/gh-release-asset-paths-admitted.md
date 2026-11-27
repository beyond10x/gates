---
format: aep.planning-md/3
id: story:gh-release-asset-paths-admitted
kind: story
status: implemented
title: gh release create and upload admit local asset paths and scan the assets
relations:
- derived_from: story:public-shared-gates
revision: 4
transitions:
- {from: "draft", to: "proposed", at: "2026-11-27T13:27:09Z", actor: "human:operator", revision: 2}
- {from: "proposed", to: "active", at: "2026-11-27T13:27:09Z", actor: "human:operator", revision: 3}
- {from: "active", to: "implemented", at: "2026-11-27T13:58:11Z", actor: "human:operator", revision: 4, decided_on: {"recorded":{"test_result":2,"review_outcome":1}}}
---
## Problem

`b10x-gates gh -- release create <tag> ... <asset path under the home directory>` was refused by
`personal-paths` for the asset's path. The gates release process publishes the static binary and
`SHA256SUMS` through the bot, so the release of 0.1.31 could not be made.

## Outcome

When `release create` or `release upload` are the first two words, every positional word after
the tag is an asset, `<path>` or `<path>#<label>`. Its directory part is not published, so
`personal-paths` does not apply to the argument's text; its base name and label are scanned with
every rule. The file's content is published and is scanned: an ELF executable with the scanner of
`scan-artifact`, any other file with the text rules as UTF-8; an unreadable file, a pattern, or a
file that is neither is refused. An option the admission does not know admits no asset. Every
other `gh` command is unchanged.

## Acceptance

`tests/api_protection_writes.rs`: an absolute asset path under the home directory with and
without a label passes; a private label, a private base name, private text content and an
unreadable asset are refused; the tag is never an asset; option values are skipped; `release
upload` the same; other verbs unchanged.

Decision: the owner's pick D66 A, relayed by the host operator on 2026-11-27.
