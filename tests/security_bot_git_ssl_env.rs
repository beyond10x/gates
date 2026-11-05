//! Security review of `story:bot-git-ssl-env`: a bot push that carries the installation
//! token verifies the remote's certificate against the default authorities, whatever
//! the repository's own configuration, which `bot_command` still reads, says for the
//! push URL. The unit forces `http.sslVerify=true` on Git's command line, which wins
//! over the same key in every configuration file but not over a URL-scoped
//! `http.<url>.sslVerify`, and it removes the caller's `GIT_SSL_CAINFO` and
//! `GIT_SSL_CAPATH` but not the repository's `http.sslCAInfo` and `http.sslCAPath`.
//! Each case pushes with `bot_git` and a credential to a local bare repository, and the
//! repository's `pre-push` hook, which runs with the push's own environment and
//! command-line configuration, records what Git's URL matching gives each key for a
//! push to GitHub. Nothing reaches the network and no case changes this process's
//! environment.
use b10x_gates::delivery::bot_git;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Command, Stdio},
};

/// A stand-in for the installation token: the bot's Git runs as it does with one.
const CREDENTIAL: &str = "w2u2sec-canary-credential-not-a-token";

/// The URL whose `http.*` settings the hook asks Git for: a push to GitHub.
const GITHUB: &str = "https://github.com/beyond10x/gates";

fn scratch() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("w2u2sec-")
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

/// A `pre-push` hook that writes `<key>=<value>` to `record` for `http.sslVerify`,
/// `http.sslCAInfo` and `http.sslCAPath` as Git resolves them for `GITHUB` in the
/// push's environment; an unset key is written with an empty value.
fn recording_hook(repository: &Path, record: &Path) {
    let path = repository.join(".git/hooks/pre-push");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(
        &path,
        format!(
            "#!/bin/sh\n\
             printf 'sslverify=%s\\n' \"$(git config --bool --get-urlmatch http.sslverify {GITHUB})\" >> '{record}'\n\
             printf 'sslcainfo=%s\\n' \"$(git config --get-urlmatch http.sslcainfo {GITHUB})\" >> '{record}'\n\
             printf 'sslcapath=%s\\n' \"$(git config --get-urlmatch http.sslcapath {GITHUB})\" >> '{record}'\n\
             cat > /dev/null\n\
             exit 0\n",
            record = record.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// What the bot's push of `main` resolves for `GITHUB`, from a work repository whose
/// own configuration holds `config`.
fn bot_push_resolves(config: &[(&str, &str)]) -> BTreeMap<String, String> {
    let remote = scratch();
    git(remote.path(), &["init", "--quiet", "--bare", "--template="]);
    let work = scratch();
    git(
        work.path(),
        &["init", "--quiet", "-b", "main", "--template="],
    );
    fs::write(work.path().join("file.txt"), "file\n").unwrap();
    git(work.path(), &["add", "file.txt"]);
    git(work.path(), &["commit", "--quiet", "-m", "file"]);
    for (key, value) in config {
        git(work.path(), &["config", key, value]);
    }
    let record = scratch();
    let record = record.path().join("pre-push");
    recording_hook(work.path(), &record);
    let args: Vec<String> = [
        "push",
        "--quiet",
        remote.path().to_str().unwrap(),
        "main:refs/heads/pushed",
    ]
    .map(String::from)
    .to_vec();
    bot_git(work.path(), &args, Some(CREDENTIAL)).expect("fixture: the bot's push failed");
    let lines = fs::read_to_string(&record).expect("fixture: the pre-push hook did not run");
    lines
        .lines()
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

/// `http.https://github.com/.sslVerify=false` in the repository's `.git/config` is more
/// specific for a push to GitHub than the `http.sslVerify=true` the bot puts on Git's
/// command line, so Git's URL matching takes it and the token's push runs without
/// certificate verification. Story proposal: "and `http.sslVerify` through any config
/// path the bot still reads".
#[test]
fn a_url_scoped_ssl_verify_off_in_the_repository_does_not_reach_the_bot_push() {
    let resolved = bot_push_resolves(&[("http.https://github.com/.sslVerify", "false")]);
    assert_eq!(
        resolved.get("sslverify").map(String::as_str),
        Some("true"),
        "the bot's push to {GITHUB} would run with http.sslVerify {:?} from the \
         repository's URL-scoped configuration",
        resolved.get("sslverify")
    );
}

/// `http.sslCAInfo` in the repository's `.git/config` makes the bot's push trust the
/// authority in the file it names, as the removed `GIT_SSL_CAINFO` would.
#[test]
fn a_repository_ca_file_does_not_reach_the_bot_push() {
    let resolved = bot_push_resolves(&[("http.sslCAInfo", "/nonexistent/interceptor-ca.pem")]);
    assert_eq!(
        resolved.get("sslcainfo").map(String::as_str),
        Some(""),
        "the bot's push to {GITHUB} would trust the authority in {:?} from the \
         repository's configuration",
        resolved.get("sslcainfo")
    );
}

/// `http.sslCAPath` in the repository's `.git/config` makes the bot's push trust every
/// authority in the directory it names, as the removed `GIT_SSL_CAPATH` would.
#[test]
fn a_repository_ca_directory_does_not_reach_the_bot_push() {
    let resolved = bot_push_resolves(&[("http.sslCAPath", "/nonexistent/interceptor-certs")]);
    assert_eq!(
        resolved.get("sslcapath").map(String::as_str),
        Some(""),
        "the bot's push to {GITHUB} would trust the authorities in {:?} from the \
         repository's configuration",
        resolved.get("sslcapath")
    );
}
