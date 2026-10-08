//! `b10x-gates bot` refuses unsupported Git operations before minting a token, and
//! names the supported route. These tests call the pure argument check only.
use b10x_gates::bot_args::check;

fn args(line: &str) -> Vec<String> {
    line.split_whitespace().map(String::from).collect()
}

fn refusal(line: &str, repository: Option<&str>) -> String {
    match check(&args(line), repository) {
        Ok(()) => panic!("`{line}` passed the bot argument check"),
        Err(error) => format!("{error:#}"),
    }
}

#[test]
fn merge_refusal_prints_no_commit_route() {
    let text = refusal("merge feature", None);
    assert!(text.contains("git merge --no-ff --no-commit"), "{text}");
    assert!(text.contains("b10x-gates bot -- commit -F -"), "{text}");
    assert!(text.contains("no pathspec"), "{text}");
}

#[test]
fn pull_refusal_prints_fetch_then_merge() {
    let text = refusal("pull origin main", None);
    assert!(text.contains("b10x-gates bot -- fetch origin"), "{text}");
    assert!(text.contains("git merge --no-ff --no-commit"), "{text}");
    assert!(text.contains("b10x-gates bot -- commit -F -"), "{text}");
}

#[test]
fn rebase_refusal_prints_merge_route() {
    for verb in ["rebase main", "cherry-pick abc123", "am patch.mbox"] {
        let text = refusal(verb, None);
        assert!(text.contains("pre-push check"), "{verb}: {text}");
        assert!(
            text.contains("git merge --no-ff --no-commit"),
            "{verb}: {text}"
        );
        assert!(
            text.contains("b10x-gates bot -- commit -F -"),
            "{verb}: {text}"
        );
    }
}

#[test]
fn push_delete_forms_are_refused_with_api_route() {
    for line in [
        "push --delete origin x",
        "push -d origin x",
        "push origin :x",
    ] {
        let text = refusal(line, None);
        assert!(
            text.contains("b10x-gates api --method DELETE --path /repos/<owner>/<repo>/git/refs/heads/x --output <file>"),
            "{line}: {text}"
        );
        assert!(text.contains("policy"), "{line}: {text}");
    }
    for line in ["push --prune origin", "push --mirror origin"] {
        let text = refusal(line, None);
        assert!(
            text.contains("b10x-gates api --method DELETE --path /repos/<owner>/<repo>/git/refs/heads/<branch>"),
            "{line}: {text}"
        );
    }
    let text = refusal("push origin +:refs/heads/y", Some("example/sample"));
    assert!(
        text.contains("--path /repos/example/sample/git/refs/heads/y "),
        "{text}"
    );
    for line in [
        "push origin main -- --delete",
        "push --del origin x",
        "push -fd origin x",
        "push origin main :x",
    ] {
        refusal(line, None);
    }
}

#[test]
fn other_verbs_are_refused_with_the_supported_verbs() {
    for line in [
        "reset --hard",
        "-C elsewhere push origin main",
        "switch main",
    ] {
        let text = refusal(line, None);
        assert!(
            text.contains("commit, tag, push or fetch"),
            "{line}: {text}"
        );
        assert!(
            text.contains("git merge --no-ff --no-commit"),
            "{line}: {text}"
        );
        assert!(text.contains("--method DELETE"), "{line}: {text}");
    }
    assert!(check(&[], None).is_err());
}

#[test]
fn supported_verbs_pass_the_check() {
    for line in [
        "commit -F - -- a",
        "tag -a v -m m",
        "push origin main",
        "push origin main:main",
        "push --progress origin main",
        "fetch origin",
    ] {
        check(&args(line), None).unwrap_or_else(|e| panic!("`{line}` refused: {e:#}"));
    }
}

#[test]
fn existing_guards_still_refuse() {
    for line in [
        "commit --no-verify -F -",
        "push -n origin main",
        "push -c core.hooksPath=x origin main",
        "fetch --config-env=core.hooksPath=X origin",
        "push --exec=elsewhere origin main",
    ] {
        let text = refusal(line, None);
        assert!(
            text.contains("bot delivery cannot bypass hooks or inject Git configuration"),
            "{line}: {text}"
        );
    }
}
