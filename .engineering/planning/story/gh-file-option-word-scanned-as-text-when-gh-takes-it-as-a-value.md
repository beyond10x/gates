---
format: aep.planning-md/3
id: story:gh-file-option-word-scanned-as-text-when-gh-takes-it-as-a-value
kind: story
status: draft
title: A word after a file option is scanned as text when gh takes the option word as another option's value
relations:
- derived_from: story:public-shared-gates
revision: 1
---
## Context

`b10x-gates gh -- <args>` reads the word after `--input`, `--body-file` or `--notes-file` as a
file and scans only the file's content, never the word itself (`src/main.rs`, the `FILE_OPTIONS`
branch of the `gh` verb). That is right when `gh` reads the word as that option's value. It is
wrong when `gh` takes the option word as the value of the option before it: `gh api -p --input
<path>` gives `--preview` the value `--input` and requests `<path>` as the endpoint, so the path
text, a home directory for example, goes into the request URL unscanned, as long as a clean file
exists at that path.

Found by the security review of pull request 62 (the `run download` directory admission). It is
older than that change: the file-option branch is unchanged by it. Rated a warning: no documented
call reaches it; it needs the misplaced option word and an existing file at the path.

## Planned scope

- `src/main.rs`: read a word as a file only where `gh` reads it as the value of a file option,
  with the same value-skipping as `local_directories` (an option that takes a value takes the
  next word, even one that starts with `-`); otherwise scan the word as text.
- Scanning the path text of every file option is not the fix: callers pass `--body-file` paths
  under the home directory, and only the file's content is published.
- `tests/api_protection_writes.rs`: the red case below, and cases that a real `--body-file`
  under the home directory still passes.

## Acceptance

- `gh -- api -p --input <path under the home directory>` is refused for `personal-paths` (state
  transition: the scan refuses before the token step).
- `gh -- pr create --body-file <path under the home directory>` with a clean file still passes the
  scan (state transition: none).

## Red case

The case written by the review, as a patch on `tests/api_protection_writes.rs` at the head of
pull request 62:

```diff
diff --git a/tests/api_protection_writes.rs b/tests/api_protection_writes.rs
index cccdf4a..53fc1d7 100644
--- a/tests/api_protection_writes.rs
+++ b/tests/api_protection_writes.rs
@@ -1154,3 +1154,23 @@ fn run_download_directory_that_is_not_utf8_never_reaches_the_token_step() {
     assert!(!run.ok, "{}", run.stderr);
     assert!(!run.stderr.contains(ABSENT_BOT), "{}", run.stderr);
 }
+
+/// Found in this review, before the `run download` admission (the file-option branch is
+/// unchanged by it): a word after `--input`, `--body-file` or `--notes-file` is read as a
+/// file and only its content is scanned, even when `gh` takes that option word as the value
+/// of the option before it. `gh api -p --input <path>` gives `--preview` the value `--input`
+/// and requests `<path>` as the endpoint, so the path, a home directory here, goes into the
+/// request URL.
+#[test]
+fn a_path_gh_takes_for_the_endpoint_after_a_file_option_word_is_scanned_as_text() {
+    let sandbox = Sandbox::new().with_policy();
+    let relative = ["d", "", "home", "fixture-person", "f"].join("/");
+    fs::create_dir_all(sandbox.path().join("d/home/fixture-person")).unwrap();
+    sandbox.file("d/home/fixture-person/f", b"{}\n");
+    let mut command = sandbox.command();
+    command
+        .arg("--repo")
+        .arg(sandbox.path())
+        .args(["gh", "--", "api", "-p", "--input", &relative]);
+    scan_refused(&sandbox.run(command), 4, &["personal-paths"]);
+}
```
