---
format: aep.planning-md/3
id: story:release-static-name-service
kind: story
status: active
title: Refuse a static glibc release executable, which crashes on its second name lookup
revision: 3
transitions:
- {from: "draft", to: "proposed", at: "2026-10-13T19:21:23Z", actor: "human:timo", revision: 2}
- {from: "proposed", to: "active", at: "2026-10-13T19:21:23Z", actor: "human:timo", revision: 3}
---
## Problem

`b10x-gates bot -- delete-branch <branch>` (0.1.19) exits 139 (SIGSEGV) and prints nothing,
with and without `--repository`. Reproduced 2026-10-13 in a gates checkout with a branch that
does not exist (`wave/no-such-branch-xyz`), so nothing could be deleted: 0.1.19 exits 139, the
0.1.18 release asset answers "remote branch ... does not exist". `b10x-gates api --method GET
--path /repos/beyond10x/gates` crashes the same way on 0.1.19 and succeeds on 0.1.18.

Cause, observed at runtime: the 0.1.19 release asset is a static-pie linked against glibc
(`.comment` names GCC 16.2.1 and LLD; it carries `.note.ABI-tag` and `nsswitch.conf`); 0.1.17
and 0.1.18 were musl builds (crt from GCC 9.4.0, no NSS strings). Traced with `strace -f`: the
first GitHub request (minting the installation token) resolves `api.github.com` by loading
`libnss_resolve.so.2` from the host; the second request, on a new client's runtime thread,
connects to systemd-resolved through that module and faults at address 0. A statically linked
glibc cannot safely run a host NSS module. Every verb that makes two GitHub requests dies
(`delete-branch`, `api`); `commit` and `push` make one, which is why they worked.

The source is unchanged between 0.1.18 and 0.1.19 in this respect: the release build target
changed, and nothing checked it.

## Proposal

- `scan-artifact`, which every release executable passes before publication, refuses a
  statically linked executable (no `PT_INTERP`) that carries glibc's NSS loader
  (`nsswitch.conf`), before any scanner runs, naming the musl target.
- The release section of the README names the build: `--target x86_64-unknown-linux-musl`.
- Spec first: `gates.delivery.ValidateArtifact` with the `static-name-service` outcome.

## Acceptance

- A test builds a static ELF fixture carrying `nsswitch.conf` and sees `scan-artifact` refuse
  it with the musl target named and zero scanner invocations; it fails on 0.1.19's source.
- The same fixture with a `PT_INTERP` header (dynamic) is not refused by this rule.
- A static ELF without the NSS marker (musl) still validates.
- The 0.1.20 asset, built for musl, runs `bot -- delete-branch <missing branch>` to the
  "does not exist" refusal on this host, and `scan-artifact` admits it.
