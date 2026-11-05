//! `story:bot-git-ssl-env`: the caller's TLS settings for Git (`GIT_SSL_NO_VERIFY` and
//! every other `GIT_SSL_*` variable) and `SSLKEYLOGFILE`, which makes Git's TLS library
//! write the session secrets that decrypt the request carrying the installation token,
//! reach no bot Git process: not a `bot -- push`, not a `bot -- fetch`, not the
//! scratch push of `delete-branch`, not the `ci` fetch that carries the workflow token.
//! The repository's own configuration, which the bot's Git still reads, changes neither
//! the TLS settings of a GitHub request (`http.sslVerify`, `http.sslCAInfo` and the
//! rest, for any URL, through any include) nor a GitHub URL (`url.<base>.insteadOf`,
//! `url.<base>.pushInsteadOf`), and the bot's credential helper answers no proxy.
//! Every case runs a child entry point of this binary with the environment under test
//! and reads what a hook of the bot's Git recorded, against local bare repositories, so
//! no case changes this process's environment and nothing reaches the network.
use b10x_gates::{
    delivery::{bot_git, ci_candidate_from, compare_and_delete_branch},
    policy::{Policy, Repository},
};
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

/// A stand-in for the installation token: the bot's Git runs as it does with one.
const CREDENTIAL: &str = "w2u2-canary-credential-not-a-token";

/// Each variable the bot's Git must not inherit, with a value Git would act on.
/// `GIT_SSL_A_LATER_SETTING` is no variable Git reads today: it stands for one a later
/// Git adds under the same prefix.
const REMOVED: [(&str, &str); 12] = [
    ("GIT_SSL_NO_VERIFY", "1"),
    ("GIT_SSL_CAINFO", "/nonexistent/ca.pem"),
    ("GIT_SSL_CAPATH", "/nonexistent/certs"),
    ("GIT_SSL_CERT", "/nonexistent/client.pem"),
    ("GIT_SSL_KEY", "/nonexistent/client.key"),
    ("GIT_SSL_CERT_TYPE", "PEM"),
    ("GIT_SSL_KEY_TYPE", "PEM"),
    ("GIT_SSL_CERT_PASSWORD_PROTECTED", "1"),
    ("GIT_SSL_CIPHER_LIST", "NULL"),
    ("GIT_SSL_VERSION", "tlsv1.0"),
    ("GIT_SSL_A_LATER_SETTING", "1"),
    ("SSLKEYLOGFILE", "/nonexistent/keys.log"),
];

/// A variable no bot Git process has a reason to drop: a hook that sees it sees the
/// caller's environment, so an absent `REMOVED` name was removed, not never passed.
const CONTROL: (&str, &str) = ("W2U2_CONTROL", "1");

/// The URL whose `http.sslVerify` the hooks ask Git for: a push to GitHub.
const GITHUB: &str = "https://github.com/beyond10x/gates";

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("w2u2-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

/// `git` in `dir` with no configuration but an identity.
fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .current_dir(dir)
        .args([
            "-c",
            "user.name=example",
            "-c",
            "user.email=example@example.invalid",
        ])
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_PARAMETERS")
        .env_remove("GIT_CONFIG_COUNT")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_string()
}

/// A hook at `path` that appends the names (never the values) of its environment to
/// `<record>/<hook>-environment` and Git's `http.sslVerify` for `GITHUB`, as the
/// repository and the configuration Git hands its hooks give it, to
/// `<record>/<hook>-sslverify`.
fn recording_hook(path: &Path, record: &Path) {
    let hook = path.file_name().unwrap().to_str().unwrap();
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        path,
        format!(
            "#!/bin/sh\n\
             env | cut -d= -f1 >> '{record}/{hook}-environment'\n\
             git config --bool --get-urlmatch http.sslverify {GITHUB} >> '{record}/{hook}-sslverify'\n\
             cat > /dev/null\n\
             exit 0\n",
            record = record.display()
        ),
    )
    .unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A bare remote with `main` and `wave/one` at one commit, which is returned.
fn remote() -> (tempfile::TempDir, String) {
    let dir = scratch();
    git(dir.path(), &["init", "--quiet", "--bare", "--template="]);
    let tree = git(dir.path(), &["mktree"]);
    let tip = git(dir.path(), &["commit-tree", &tree, "-m", "change"]);
    for branch in ["main", "wave/one"] {
        git(
            dir.path(),
            &["update-ref", &format!("refs/heads/{branch}"), &tip],
        );
    }
    (dir, tip)
}

/// A work repository on `main` with one commit, whose own configuration turns TLS
/// verification off for every URL.
fn work() -> tempfile::TempDir {
    let dir = scratch();
    git(
        dir.path(),
        &["init", "--quiet", "-b", "main", "--template="],
    );
    fs::write(dir.path().join("file.txt"), "file\n").unwrap();
    git(dir.path(), &["add", "file.txt"]);
    git(dir.path(), &["commit", "--quiet", "-m", "file"]);
    git(dir.path(), &["config", "http.sslVerify", "false"]);
    dir
}

/// Run `child` of this test binary with every `REMOVED` variable, `CONTROL` and `env`:
/// its `W2U2 ` lines.
fn run_child(child: &str, env: &[(&str, &str)]) -> String {
    run_child_output(child, env).0
}

/// `run_child`, with the child's standard error as well.
fn run_child_output(child: &str, env: &[(&str, &str)]) -> (String, String) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            child,
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .envs(REMOVED.iter().copied())
        .envs([CONTROL])
        .envs(env.iter().copied())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(output.status.success(), "{child}: {stdout}\n{stderr}");
    let lines = stdout
        .lines()
        // libtest prints `test <name> ... ` before the child's first line.
        .filter_map(|line| line.find("W2U2 ").map(|at| &line[at..]))
        .collect::<Vec<_>>()
        .join("\n");
    (lines, stderr)
}

/// The `REMOVED` names in the environment `hook` recorded under `record`, after
/// checking the hook ran and saw the caller's environment at all.
fn inherited(record: &Path, hook: &str) -> Vec<&'static str> {
    let file = record.join(format!("{hook}-environment"));
    let names = fs::read_to_string(&file)
        .unwrap_or_else(|_| panic!("fixture: the {hook} hook did not run"));
    let names: Vec<&str> = names.lines().collect();
    assert!(
        names.contains(&CONTROL.0),
        "fixture: the {hook} hook did not see the caller's environment"
    );
    REMOVED
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| names.contains(name))
        .collect()
}

#[test]
#[ignore = "child process entry point: run by a_bot_push_inherits_no_tls_setting_of_the_caller, a_bot_fetch_inherits_no_tls_setting_of_the_caller, a_repository_wide_ssl_verify_off_does_not_reach_the_bot, every_repository_tls_setting_is_overridden_for_the_bot_push, every_included_repository_tls_setting_is_overridden_for_the_bot_push, no_repository_rewrite_moves_a_github_url_of_the_bot, a_github_rewrite_the_bot_cannot_override_is_refused_before_anything_is_sent and the_bot_credential_answers_the_repository_and_no_proxy"]
fn child_bot_git() {
    let root = std::env::var("W2U2_ROOT").unwrap();
    let args: Vec<String> = std::env::var("W2U2_ARGS")
        .unwrap()
        .split(' ')
        .map(String::from)
        .collect();
    let outcome =
        bot_git(Path::new(&root), &args, Some(CREDENTIAL)).map_err(|error| format!("{error:#}"));
    println!("W2U2 {} {outcome:?}", args[0]);
}

#[test]
#[ignore = "child process entry point: run by the_delete_branch_push_inherits_no_tls_setting_of_the_caller"]
fn child_compare_and_delete() {
    let remote = std::env::var("W2U2_REMOTE").unwrap();
    let tip = std::env::var("W2U2_TIP").unwrap();
    let outcome = compare_and_delete_branch(&remote, "wave/one", &tip, Some(CREDENTIAL))
        .map_err(|error| format!("{error:#}"));
    println!("W2U2 delete {outcome:?}");
}

/// `bot -- push` with the caller's TLS settings: Git's `pre-push` hook, which runs with
/// the push's own environment, sees none of them.
fn push_recorded() -> (tempfile::TempDir, tempfile::TempDir) {
    let (remote, _) = remote();
    let root = work();
    let record = scratch();
    recording_hook(&root.path().join(".git/hooks/pre-push"), record.path());
    let args = format!(
        "push --quiet {} main:refs/heads/pushed",
        remote.path().display()
    );
    let lines = run_child(
        "child_bot_git",
        &[
            ("W2U2_ROOT", root.path().to_str().unwrap()),
            ("W2U2_ARGS", &args),
        ],
    );
    assert!(
        lines.contains("W2U2 push Ok(())"),
        "fixture: the push failed:\n{lines}"
    );
    (root, record)
}

#[test]
fn a_bot_push_inherits_no_tls_setting_of_the_caller() {
    let (_root, record) = push_recorded();
    let leaked = inherited(record.path(), "pre-push");
    assert!(
        leaked.is_empty(),
        "the bot's push inherited the caller's {leaked:?}"
    );
}

/// `http.sslVerify=false` in the repository's own `.git/config` applies to every URL;
/// the bot's Git gives Git the opposite on its command line, which wins over every
/// configuration file for the same key. A URL-scoped `http.<url>.sslVerify` is more
/// specific than that key: `every_repository_tls_setting_is_overridden_for_the_bot_push`
/// covers it.
#[test]
fn a_repository_wide_ssl_verify_off_does_not_reach_the_bot() {
    let (_root, record) = push_recorded();
    let verify = fs::read_to_string(record.path().join("pre-push-sslverify")).unwrap();
    assert_eq!(
        verify.trim(),
        "true",
        "the bot's push to {GITHUB} would run with http.sslVerify {:?} from the \
         repository's configuration",
        verify.trim()
    );
}

/// `bot -- fetch` with the caller's TLS settings: the `reference-transaction` hook, run
/// by the fetch when it updates a ref, sees none of them.
#[test]
fn a_bot_fetch_inherits_no_tls_setting_of_the_caller() {
    let (remote, _) = remote();
    let root = work();
    let record = scratch();
    recording_hook(
        &root.path().join(".git/hooks/reference-transaction"),
        record.path(),
    );
    let args = format!(
        "fetch --quiet {} refs/heads/main:refs/remotes/probe/main",
        remote.path().display()
    );
    let lines = run_child(
        "child_bot_git",
        &[
            ("W2U2_ROOT", root.path().to_str().unwrap()),
            ("W2U2_ARGS", &args),
        ],
    );
    assert!(
        lines.contains("W2U2 fetch Ok(())"),
        "fixture: the fetch failed:\n{lines}"
    );
    let leaked = inherited(record.path(), "reference-transaction");
    assert!(
        leaked.is_empty(),
        "the bot's fetch inherited the caller's {leaked:?}"
    );
    let verify = fs::read_to_string(record.path().join("reference-transaction-sslverify")).unwrap();
    assert!(
        !verify.is_empty() && verify.lines().all(|line| line == "true"),
        "the bot's fetch would run with http.sslVerify {verify:?}"
    );
}

/// The scratch push of `delete-branch`, which carries the credential: the remote's
/// `pre-receive` hook, run with the environment of the `git-receive-pack` that push
/// starts, sees none of the caller's TLS settings.
#[test]
fn the_delete_branch_push_inherits_no_tls_setting_of_the_caller() {
    let (remote, tip) = remote();
    let record = scratch();
    recording_hook(&remote.path().join("hooks/pre-receive"), record.path());
    let lines = run_child(
        "child_compare_and_delete",
        &[
            ("W2U2_REMOTE", remote.path().to_str().unwrap()),
            ("W2U2_TIP", &tip),
        ],
    );
    assert!(
        lines.contains("W2U2 delete Ok(Deleted)"),
        "fixture: the deletion did not run:\n{lines}"
    );
    let leaked = inherited(record.path(), "pre-receive");
    assert!(
        leaked.is_empty(),
        "the delete-branch push inherited the caller's {leaked:?}"
    );
}

// --- `ci`'s fetch ---------------------------------------------------------------------

#[test]
#[ignore = "child process entry point: run by the_ci_fetch_inherits_no_tls_setting_of_the_caller"]
fn child_ci_fetch() {
    let remote = std::env::var("W2U2_REMOTE").unwrap();
    let tip = std::env::var("W2U2_TIP").unwrap();
    let dir = scratch();
    let event = dir.path().join("event.json");
    let body = serde_json::json!({
        "after": tip,
        "repository": {"id": 123, "full_name": "example/repository"}
    });
    fs::write(&event, serde_json::to_vec(&body).unwrap()).unwrap();
    let policy = Policy {
        version: 2,
        nonce: "synthetic-policy-nonce-for-bot-git-ssl-env-1234".into(),
        forbidden_literals: vec![],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::from([(
            "example/repository".into(),
            Repository {
                id: "123".into(),
                baseline: tip.clone(),
            },
        )]),
        signers: BTreeMap::new(),
        exceptions: vec![],
    };
    let outcome = ci_candidate_from(&policy, &event, &dir.path().join("candidate.git"), |_| {
        remote.clone()
    })
    .map(|_| ())
    .map_err(|error| format!("{error:#}"));
    println!("W2U2 ci {outcome:?}");
}

/// `ci`'s fetch, which carries the workflow token, with the caller's TLS settings and a
/// Trace2 target that records, for each Git process, the value of every `REMOVED` name
/// and of `CONTROL` it has (`GIT_TRACE2_ENV_VARS`): the fetch, and each process it
/// starts, has none of `REMOVED`.
#[test]
fn the_ci_fetch_inherits_no_tls_setting_of_the_caller() {
    let (remote, tip) = remote();
    let record = scratch();
    let trace = record.path().join("trace2.json");
    let names: Vec<&str> = REMOVED
        .iter()
        .map(|(name, _)| *name)
        .chain([CONTROL.0])
        .collect();
    let lines = run_child(
        "child_ci_fetch",
        &[
            ("W2U2_REMOTE", remote.path().to_str().unwrap()),
            ("W2U2_TIP", &tip),
            ("GITHUB_TOKEN", CREDENTIAL),
            ("GIT_TRACE2_EVENT", trace.to_str().unwrap()),
            ("GIT_TRACE2_ENV_VARS", &names.join(",")),
        ],
    );
    assert!(
        lines.contains("W2U2 ci "),
        "fixture: ci did not run:\n{lines}"
    );
    let events: Vec<serde_json::Value> = fs::read_to_string(&trace)
        .expect("fixture: no Git process wrote a trace")
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let fetches: Vec<&str> = events
        .iter()
        .filter(|event| {
            event["event"] == "start"
                && event["argv"]
                    .as_array()
                    .is_some_and(|argv| argv.iter().any(|arg| arg == "fetch"))
        })
        .filter_map(|event| event["sid"].as_str())
        .collect();
    assert!(
        !fetches.is_empty(),
        "fixture: no fetch in the trace:\n{lines}"
    );
    let seen: Vec<&str> = events
        .iter()
        .filter(|event| {
            event["event"] == "def_param"
                && event["sid"].as_str().is_some_and(|sid| {
                    fetches
                        .iter()
                        .any(|fetch| sid == *fetch || sid.starts_with(&format!("{fetch}/")))
                })
        })
        .filter_map(|event| event["param"].as_str())
        .collect();
    assert!(
        seen.contains(&CONTROL.0),
        "fixture: the fetch's trace shows no variable of the caller"
    );
    let leaked: Vec<&str> = names
        .iter()
        .copied()
        .filter(|name| *name != CONTROL.0 && seen.contains(name))
        .collect();
    assert!(
        leaked.is_empty(),
        "the ci fetch inherited the caller's {leaked:?}"
    );
}

// --- the repository's own configuration -----------------------------------------------

/// Each `http.*` setting that chooses whether Git checks GitHub's certificate, which
/// authorities it trusts, which client certificate it offers, which TLS library,
/// protocol version or ciphers it uses, or which address GitHub resolves to, as Git
/// spells it; a value Git would act on; and the value the bot's push resolves instead.
const REPOSITORY_TLS: [(&str, &str, &str); 16] = [
    ("sslVerify", "false", "true"),
    ("sslCAInfo", "/nonexistent/ca.pem", ""),
    ("sslCAPath", "/nonexistent/certs", ""),
    ("sslCert", "/nonexistent/client.pem", ""),
    ("sslKey", "/nonexistent/client.key", ""),
    ("sslCertType", "P12", ""),
    ("sslKeyType", "ENG", ""),
    ("sslCertPasswordProtected", "true", "false"),
    ("sslBackend", "gnutls", ""),
    ("sslVersion", "tlsv1.0", ""),
    ("sslCipherList", "NULL", ""),
    ("proxySSLCAInfo", "/nonexistent/proxy-ca.pem", ""),
    ("proxySSLCert", "/nonexistent/proxy-client.pem", ""),
    ("proxySSLKey", "/nonexistent/proxy-client.key", ""),
    ("proxySSLCertPasswordProtected", "true", "false"),
    ("curloptResolve", "github.com:443:192.0.2.1", ""),
];

/// A bot push run by `hooked_push`, with what it left behind.
struct Hooked {
    record: tempfile::TempDir,
    remote: tempfile::TempDir,
    _root: tempfile::TempDir,
    /// The child's `W2U2 ` lines.
    lines: String,
    /// The child's standard error: the bot's and Git's messages.
    stderr: String,
}

/// `bot -- push` of `main` to a new bare remote, in a child with the caller's TLS
/// settings, from a work repository whose own configuration also holds `config`
/// (`git config --add`, in order). The work repository's `pre-push` hook runs `hook`
/// with `$RECORD` naming a directory it may write to.
fn hooked_push(config: &[(&str, &str)], hook: &str) -> Hooked {
    let (remote, _) = remote();
    let root = work();
    for (key, value) in config {
        git(root.path(), &["config", "--add", key, value]);
    }
    let record = scratch();
    let path = root.path().join(".git/hooks/pre-push");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        format!(
            "#!/bin/sh\nRECORD='{}'\n{hook}\ncat > /dev/null\nexit 0\n",
            record.path().display()
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    let args = format!(
        "push --quiet {} main:refs/heads/pushed",
        remote.path().display()
    );
    let (lines, stderr) = run_child_output(
        "child_bot_git",
        &[
            ("W2U2_ROOT", root.path().to_str().unwrap()),
            ("W2U2_ARGS", &args),
        ],
    );
    Hooked {
        record,
        remote,
        _root: root,
        lines,
        stderr,
    }
}

/// A `pre-push` hook body that records every `http.*` setting Git resolves for `GITHUB`
/// with the push's own configuration.
fn http_hook() -> String {
    format!("git config --null --get-urlmatch http {GITHUB} > \"$RECORD/http\"")
}

/// What `http_hook` recorded: each `http.*` key, lower case without `http.`, and its
/// value, after checking the push ran.
fn resolved_http(hooked: &Hooked) -> BTreeMap<String, String> {
    assert!(
        hooked.lines.contains("W2U2 push Ok(())"),
        "fixture: the push failed:\n{}\n{}",
        hooked.lines,
        hooked.stderr
    );
    fs::read_to_string(hooked.record.path().join("http"))
        .expect("fixture: the pre-push hook did not run")
        .split('\0')
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let (key, value) = entry.split_once('\n').unwrap_or((entry, ""));
            let key = key.strip_prefix("http.").unwrap_or(key);
            (key.to_owned(), value.to_owned())
        })
        .collect()
}

/// Every `REPOSITORY_TLS` setting in the repository's `.git/config` for the push URL
/// itself, `http.<GITHUB>.<key>`, the most specific key Git's URL matching can select
/// and so one the bot's `http.<key>` on Git's command line does not win over: the
/// bot's push resolves each to the bot's value. The bot names each key it overrides on
/// its standard error, with the URL left out, and never a value.
#[test]
fn every_repository_tls_setting_is_overridden_for_the_bot_push() {
    let keys: Vec<(String, &str)> = REPOSITORY_TLS
        .iter()
        .map(|(key, value, _)| (format!("http.{GITHUB}.{key}"), *value))
        .collect();
    let config: Vec<(&str, &str)> = keys
        .iter()
        .map(|(key, value)| (key.as_str(), *value))
        .collect();
    let hooked = hooked_push(&config, &http_hook());
    let resolved = resolved_http(&hooked);
    for (key, set, expected) in REPOSITORY_TLS {
        assert_eq!(
            resolved.get(&key.to_lowercase()).map(String::as_str),
            Some(expected),
            "the bot's push to {GITHUB} resolves http.{key} from the repository's \
             http.<url>.{key}={set}"
        );
        assert!(
            hooked
                .stderr
                .contains(&format!("http.<url>.{}", key.to_lowercase())),
            "the bot does not name the http.<url>.{key} it overrides:\n{}",
            hooked.stderr
        );
    }
    for withheld in ["/nonexistent/", "github.com/beyond10x", "192.0.2.1"] {
        assert!(
            !hooked.stderr.contains(withheld),
            "the bot printed a value of the repository's configuration:\n{}",
            hooked.stderr
        );
    }
}

/// The same settings for every URL, `http.<key>`, in a file the repository's
/// configuration includes (`include.path`), which a push reads as it reads
/// `.git/config`: the bot's push resolves each to the bot's value.
#[test]
fn every_included_repository_tls_setting_is_overridden_for_the_bot_push() {
    let included = scratch();
    let file = included.path().join("tls.gitconfig");
    let body: String = REPOSITORY_TLS
        .iter()
        .map(|(key, value, _)| format!("\t{key} = {value}\n"))
        .collect();
    fs::write(&file, format!("[http]\n{body}")).unwrap();
    let hooked = hooked_push(&[("include.path", file.to_str().unwrap())], &http_hook());
    let resolved = resolved_http(&hooked);
    for (key, set, expected) in REPOSITORY_TLS {
        assert_eq!(
            resolved.get(&key.to_lowercase()).map(String::as_str),
            Some(expected),
            "the bot's push to {GITHUB} resolves http.{key} from an included http.{key}={set}"
        );
    }
}

/// Rewrites, in the repository's configuration, of a URL the bot's credential is used
/// for, each on its own: of less of `https://github.com/` than the whole prefix, of all
/// of it and of more, each as `insteadOf` and as `pushInsteadOf`, and of the SSH forms
/// the bot itself rewrites to `https://github.com/` for a push, for the same prefix as
/// the bot's and for a longer one.
const REWRITES: [(&str, &str); 10] = [
    ("url.http://.insteadOf", "https://"),
    ("url.http://github.com/.insteadOf", "https://github.com/"),
    (
        "url.http://github.com/beyond10x/.insteadOf",
        "https://github.com/beyond10x/",
    ),
    ("url.http://.pushInsteadOf", "https://"),
    (
        "url.http://github.com/.pushInsteadOf",
        "https://github.com/",
    ),
    (
        "url.http://github.com/beyond10x/.pushInsteadOf",
        "https://github.com/beyond10x/",
    ),
    ("url.http://github.com/.pushInsteadOf", "git@github.com:"),
    (
        "url.http://github.com/.pushInsteadOf",
        "ssh://git@github.com/",
    ),
    (
        "url.http://github.com/beyond10x/.pushInsteadOf",
        "git@github.com:beyond10x/",
    ),
    (
        "url.http://github.com/beyond10x/.pushInsteadOf",
        "ssh://git@github.com/beyond10x/",
    ),
];

/// The bot's push from a repository with no rewrite, then with each of `REWRITES`: the
/// `pre-push` hook reads, with the push's own configuration, the URL a fetch of
/// `GITHUB` uses and the push URL of a remote at `GITHUB`, at
/// `git@github.com:beyond10x/gates` and at `ssh://git@github.com/beyond10x/gates`, and
/// each is `GITHUB`.
#[test]
fn no_repository_rewrite_moves_a_github_url_of_the_bot() {
    let remotes = [
        ("remote.https.url", GITHUB),
        ("remote.scp.url", "git@github.com:beyond10x/gates"),
        ("remote.ssh.url", "ssh://git@github.com/beyond10x/gates"),
    ];
    let hook = format!(
        "printf 'fetch=%s\\n' \"$(git ls-remote --get-url {GITHUB})\" >> \"$RECORD/urls\"\n\
         for remote in https scp ssh; do\n\
         printf '%s=%s\\n' $remote \"$(git remote get-url --push $remote)\" >> \"$RECORD/urls\"\n\
         done"
    );
    for rule in std::iter::once(None).chain(REWRITES.iter().map(Some)) {
        let mut config = remotes.to_vec();
        config.extend(rule.copied());
        let hooked = hooked_push(&config, &hook);
        assert!(
            hooked.lines.contains("W2U2 push Ok(())"),
            "fixture: the push failed with {rule:?}:\n{}\n{}",
            hooked.lines,
            hooked.stderr
        );
        let urls = fs::read_to_string(hooked.record.path().join("urls"))
            .expect("fixture: the pre-push hook did not run");
        for name in ["fetch", "https", "scp", "ssh"] {
            assert!(
                urls.lines().any(|line| line == format!("{name}={GITHUB}")),
                "with the repository's {rule:?}, the bot's {name} URL is not {GITHUB}:\n{urls}"
            );
        }
    }
}

/// A rewrite of a GitHub URL whose prefix holds a line break is one the bot cannot
/// override: no configuration key can name it. The bot refuses before Git runs, names
/// the key with its base left out and never its prefix, and nothing reaches the remote.
#[test]
fn a_github_rewrite_the_bot_cannot_override_is_refused_before_anything_is_sent() {
    let hooked = hooked_push(
        &[(
            "url.http://w2u2-base.invalid/.insteadOf",
            "https://github.com/beyond10x/\nw2u2-second-line",
        )],
        "touch \"$RECORD/ran\"",
    );
    assert!(
        hooked.lines.contains("W2U2 push Err(") && hooked.lines.contains("url.<base>.insteadof"),
        "the bot did not refuse, naming url.<base>.insteadof:\n{}\n{}",
        hooked.lines,
        hooked.stderr
    );
    for withheld in ["w2u2-base.invalid", "w2u2-second-line"] {
        assert!(
            !hooked.lines.contains(withheld) && !hooked.stderr.contains(withheld),
            "the bot printed a value of the repository's configuration:\n{}\n{}",
            hooked.lines,
            hooked.stderr
        );
    }
    assert!(
        !hooked.record.path().join("ran").exists(),
        "Git started the push: its pre-push hook ran"
    );
    assert_eq!(
        git(hooked.remote.path(), &["for-each-ref", "refs/heads/pushed"]),
        "",
        "the push reached the remote"
    );
}

/// The bot's credential helper as the bot's Git configures it, which the `pre-push`
/// hook inherits with the credential. `git credential fill` there for the repository
/// on GitHub gets the credential; a request shaped as Git's for a proxy URL
/// (`https_proxy=https://<user>@github.com`, with or without a path), which always
/// names the proxy URL's user, gets nothing.
#[test]
fn the_bot_credential_answers_the_repository_and_no_proxy() {
    let fill = |name: &str, request: &str| {
        format!(
            "printf '{request}\\n' | GIT_TERMINAL_PROMPT=0 GIT_ASKPASS= SSH_ASKPASS= \
             git credential fill > \"$RECORD/{name}\" 2> /dev/null"
        )
    };
    let hook = [
        fill(
            "repository",
            "protocol=https\\nhost=github.com\\npath=beyond10x/gates.git\\n",
        ),
        fill(
            "proxy",
            "protocol=https\\nhost=github.com\\nusername=someone\\n",
        ),
        fill(
            "proxy-with-path",
            "protocol=https\\nhost=github.com\\nusername=someone\\npath=beyond10x/gates.git\\n",
        ),
    ]
    .join("\n");
    let hooked = hooked_push(&[], &hook);
    assert!(
        hooked.lines.contains("W2U2 push Ok(())"),
        "fixture: the push failed:\n{}\n{}",
        hooked.lines,
        hooked.stderr
    );
    let read = |name: &str| {
        fs::read_to_string(hooked.record.path().join(name))
            .unwrap_or_else(|_| panic!("fixture: the pre-push hook did not run"))
    };
    assert!(
        read("repository").contains(&format!("password={CREDENTIAL}")),
        "fixture: the bot's helper does not answer the repository request: {:?}",
        read("repository")
    );
    for name in ["proxy", "proxy-with-path"] {
        assert!(
            !read(name).contains(CREDENTIAL),
            "the bot's helper answers a {name} request with the credential"
        );
    }
}
