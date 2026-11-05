//! `story:bot-git-ssl-env`: the caller's TLS settings for Git (`GIT_SSL_NO_VERIFY` and
//! every other `GIT_SSL_*` variable) and `SSLKEYLOGFILE`, which makes Git's TLS library
//! write the session secrets that decrypt the request carrying the installation token,
//! reach no bot Git process: not a `bot -- push`, not a `bot -- fetch`, not the
//! scratch push of `delete-branch`. A repository-wide `http.sslVerify=false` in the
//! repository's own configuration does not turn verification off for the bot either.
//! Every case runs a child entry point of this binary with the environment under test
//! and reads what a hook of the bot's Git recorded, against local bare repositories, so
//! no case changes this process's environment and nothing reaches the network.
use b10x_gates::delivery::{bot_git, compare_and_delete_branch};
use std::{
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
    assert!(
        output.status.success(),
        "{child}: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    stdout
        .lines()
        // libtest prints `test <name> ... ` before the child's first line.
        .filter_map(|line| line.find("W2U2 ").map(|at| &line[at..]))
        .collect::<Vec<_>>()
        .join("\n")
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
#[ignore = "child process entry point: run by a_bot_push_inherits_no_tls_setting_of_the_caller, a_bot_fetch_inherits_no_tls_setting_of_the_caller and a_repository_wide_ssl_verify_off_does_not_reach_the_bot"]
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
/// specific than that key and is not covered here.
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
