//! Adversary cases for `story:bot-git-ssl-env`: the TLS settings a bot push to GitHub
//! runs with, when the caller's repository configuration (the one configuration the
//! bot's Git still reads) names them. `bot_command` passes `-c http.sslVerify=true`,
//! which wins over the same key in `.git/config`; these cases try the keys and routes
//! it does not cover. Each case pushes as the bot to a local bare repository and reads,
//! from the work repository's `pre-push` hook, what Git resolves for the GitHub URL
//! with the bot's own configuration (`GIT_CONFIG_PARAMETERS` reaches the hook). That
//! resolution is the `urlmatch` lookup Git's HTTP transport makes. Nothing reaches the
//! network.
use b10x_gates::delivery::bot_git;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

const CREDENTIAL: &str = "w2u2adv-canary-credential-not-a-token";

/// The URL a bot push to GitHub uses.
const GITHUB: &str = "https://github.com/beyond10x/gates";

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("w2u2adv-")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap()
}

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

/// A `pre-push` hook that writes what Git resolves for `GITHUB`: each `http.*` key as
/// `<key>=<value>` (empty when unset) and the URL a push to it goes to.
fn recording_hook(root: &Path, record: &Path) {
    let path = root.join(".git/hooks/pre-push");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let out = record.join("resolved");
    let out = out.display();
    fs::write(
        &path,
        format!(
            "#!/bin/sh\n\
             echo \"sslverify=$(git config --bool --get-urlmatch http.sslverify {GITHUB})\" >> '{out}'\n\
             echo \"sslcainfo=$(git config --get-urlmatch http.sslcainfo {GITHUB})\" >> '{out}'\n\
             echo \"sslcapath=$(git config --get-urlmatch http.sslcapath {GITHUB})\" >> '{out}'\n\
             echo \"url=$(git ls-remote --get-url {GITHUB})\" >> '{out}'\n\
             cat > /dev/null\n\
             exit 0\n"
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// A work repository on `main` with one commit and `config` lines added to its
/// `.git/config`.
fn work(config: &[(&str, &str)]) -> tempfile::TempDir {
    let dir = scratch();
    git(
        dir.path(),
        &["init", "--quiet", "-b", "main", "--template="],
    );
    fs::write(dir.path().join("file.txt"), "file\n").unwrap();
    git(dir.path(), &["add", "file.txt"]);
    git(dir.path(), &["commit", "--quiet", "-m", "file"]);
    for (key, value) in config {
        git(dir.path(), &["config", "--add", key, value]);
    }
    dir
}

#[test]
#[ignore = "child process entry point: run by every case of this file"]
fn child_bot_push() {
    let root = std::env::var("W2U2ADV_ROOT").unwrap();
    let remote = std::env::var("W2U2ADV_REMOTE").unwrap();
    let args: Vec<String> = ["push", "--quiet", &remote, "main:refs/heads/pushed"]
        .iter()
        .map(|arg| arg.to_string())
        .collect();
    let outcome =
        bot_git(Path::new(&root), &args, Some(CREDENTIAL)).map_err(|error| format!("{error:#}"));
    println!("W2U2ADV push {outcome:?}");
}

/// Push as the bot from `root` and return what its `pre-push` hook resolved, as
/// `(key, value)` pairs.
fn bot_push_resolves(root: &Path) -> Vec<(String, String)> {
    let remote = scratch();
    git(remote.path(), &["init", "--quiet", "--bare", "--template="]);
    let record = scratch();
    recording_hook(root, record.path());
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_bot_push",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("W2U2ADV_ROOT", root)
        .env("W2U2ADV_REMOTE", remote.path())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("W2U2ADV push Ok(())"),
        "fixture: the bot push failed: {stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let resolved = fs::read_to_string(record.path().join("resolved"))
        .expect("fixture: the pre-push hook did not run");
    resolved
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn value<'a>(resolved: &'a [(String, String)], key: &str) -> &'a str {
    resolved
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
        .unwrap_or_else(|| panic!("fixture: the hook resolved no {key}"))
}

/// `http.<url>.sslVerify` is more specific than `http.sslVerify`, so Git takes it over
/// the bot's command-line key: the bot's push to GitHub runs unverified.
#[test]
fn a_url_scoped_ssl_verify_off_in_the_repository_does_not_reach_the_bot_push() {
    let root = work(&[("http.https://github.com/.sslVerify", "false")]);
    let resolved = bot_push_resolves(root.path());
    assert_eq!(
        value(&resolved, "sslverify"),
        "true",
        "the bot's push to {GITHUB} runs with the repository's URL-scoped http.sslVerify"
    );
}

/// The same key through `include.path`, which the push (unlike a merge) does not refuse.
#[test]
fn a_url_scoped_ssl_verify_off_through_include_path_does_not_reach_the_bot_push() {
    let included = scratch();
    let file = included.path().join("tls.gitconfig");
    fs::write(
        &file,
        "[http \"https://github.com\"]\n\tsslVerify = false\n",
    )
    .unwrap();
    let root = work(&[("include.path", file.to_str().unwrap())]);
    let resolved = bot_push_resolves(root.path());
    assert_eq!(
        value(&resolved, "sslverify"),
        "true",
        "the bot's push to {GITHUB} runs with an included URL-scoped http.sslVerify"
    );
}

/// Control: the repository-wide key through `include.path` loses to the bot's `-c`.
#[test]
fn a_repository_wide_ssl_verify_off_through_include_path_does_not_reach_the_bot_push() {
    let included = scratch();
    let file = included.path().join("tls.gitconfig");
    fs::write(&file, "[http]\n\tsslVerify = false\n").unwrap();
    let root = work(&[("include.path", file.to_str().unwrap())]);
    let resolved = bot_push_resolves(root.path());
    assert_eq!(value(&resolved, "sslverify"), "true");
}

/// Control: the repository-wide key through `includeIf` loses to the bot's `-c`.
#[test]
fn a_repository_wide_ssl_verify_off_through_include_if_does_not_reach_the_bot_push() {
    let included = scratch();
    let file = included.path().join("tls.gitconfig");
    fs::write(&file, "[http]\n\tsslVerify = false\n").unwrap();
    let root = work(&[("includeIf.onbranch:main.path", file.to_str().unwrap())]);
    let resolved = bot_push_resolves(root.path());
    assert_eq!(value(&resolved, "sslverify"), "true");
}

/// `http.sslCAInfo` in the repository is `GIT_SSL_CAINFO` by another route: Git trusts
/// the authority it names, an interceptor's among them, behind the caller's
/// `https_proxy`, which the bot keeps.
#[test]
fn a_repository_ca_bundle_does_not_reach_the_bot_push() {
    let root = work(&[("http.sslCAInfo", "/nonexistent/interceptor-ca.pem")]);
    let resolved = bot_push_resolves(root.path());
    assert_eq!(
        value(&resolved, "sslcainfo"),
        "",
        "the bot's push to {GITHUB} trusts the repository's http.sslCAInfo"
    );
}

/// `http.sslCAPath`, the directory form of the same redirect.
#[test]
fn a_repository_ca_directory_does_not_reach_the_bot_push() {
    let root = work(&[("http.sslCAPath", "/nonexistent/interceptor-certs")]);
    let resolved = bot_push_resolves(root.path());
    assert_eq!(
        value(&resolved, "sslcapath"),
        "",
        "the bot's push to {GITHUB} trusts the repository's http.sslCAPath"
    );
}

/// `url.http://github.com/.insteadOf=https://github.com/` sends the bot's push to
/// GitHub over plain HTTP.
#[test]
fn a_repository_insteadof_to_plain_http_does_not_reach_the_bot_push() {
    let root = work(&[("url.http://github.com/.insteadOf", "https://github.com/")]);
    let resolved = bot_push_resolves(root.path());
    assert_eq!(
        value(&resolved, "url"),
        GITHUB,
        "the bot's push to {GITHUB} is rewritten by the repository's insteadOf"
    );
}
