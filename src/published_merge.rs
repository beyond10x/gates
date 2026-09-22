//! Authenticated authority for historical GitHub App merges in delivery ancestry.
use crate::{
    BOT_EMAIL, BOT_NAME,
    git::{Git, exact_identity, is_oid, unique_header},
    policy::{Policy, valid_repository},
};
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

const BOT_APP_ID: u64 = 4_579_525;
const AUTHORITY_NAME: &str = "b10x-bot-branch-authority";

/// Read evidence from the authenticated GitHub API. Production uses `Github`;
/// tests inject evidence without introducing a configurable production endpoint.
pub trait AuthenticatedRead {
    fn get(&self, path: &str) -> Result<Value>;
}

struct Authority {
    root: String,
    repository_id: u64,
    default_branch: String,
    published_head: String,
}

/// Verify the entire candidate DAG after the enrolled baseline, including side
/// branches. A caller cannot exempt an ancestor by omitting it from a list.
pub fn verify(
    git: &Git,
    policy: &Policy,
    repository: &str,
    head: &str,
    api: &impl AuthenticatedRead,
) -> Result<()> {
    ensure!(
        valid_repository(repository) && is_oid(head),
        "delivery identity invalid"
    );
    let enrolled = policy.repository(repository)?;
    ensure!(is_oid(&enrolled.baseline), "delivery baseline invalid");
    ensure!(
        git.resolve(&format!("{head}^{{commit}}"))? == head,
        "delivery head is not a commit"
    );
    git.read(&["merge-base", "--is-ancestor", &enrolled.baseline, head])
        .context("delivery head does not descend from the enrolled baseline")?;
    let commits = git.text(&[
        "rev-list",
        "--reverse",
        "--topo-order",
        &format!("{}..{head}", enrolled.baseline),
    ])?;
    let mut authority = None;
    for oid in commits.lines() {
        ensure!(is_oid(oid), "invalid ancestry object");
        if git.verify_bot(&[oid.to_owned()]).is_ok() {
            continue;
        }
        // Only this exact raw identity and shape can even request an exception.
        let raw = git.read(&["cat-file", "commit", oid])?;
        ensure!(
            exact_identity(unique_header(&raw, b"author ")?, BOT_NAME, BOT_EMAIL),
            "historical merge author is not the exact bot"
        );
        ensure!(
            exact_identity(
                unique_header(&raw, b"committer ")?,
                "GitHub",
                "noreply@github.com"
            ),
            "historical merge committer is not exact GitHub"
        );
        let parents = raw
            .split(|b| *b == b'\n')
            .take_while(|line| !line.is_empty())
            .filter_map(|line| line.strip_prefix(b"parent "))
            .map(std::str::from_utf8)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(
            parents.len() == 2 && parents.iter().all(|p| is_oid(p)),
            "historical merge must have exactly two parents"
        );
        let tree = std::str::from_utf8(unique_header(&raw, b"tree ")?)?;
        ensure!(is_oid(tree), "historical merge tree invalid");
        git.read(&["cat-file", "-e", &format!("{tree}^{{tree}}")])?;
        if authority.is_none() {
            authority = Some(Authority::load(git, api, repository, &enrolled.id)?);
        }
        authority
            .as_ref()
            .context("remote authority unavailable")?
            .verify_merge(git, api, repository, oid, tree, &parents)?;
    }
    Ok(())
}

fn string<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    value
        .pointer(pointer)
        .and_then(Value::as_str)
        .context("required remote identity missing")
}

fn oid<'a>(value: &'a Value, pointer: &str) -> Result<&'a str> {
    let id = string(value, pointer)?;
    ensure!(is_oid(id), "remote object identity invalid");
    Ok(id)
}

fn pages(api: &impl AuthenticatedRead, path: &str) -> Result<Vec<Value>> {
    let separator = if path.contains('?') { '&' } else { '?' };
    let mut items = Vec::new();
    for page in 1..=20 {
        let result = api.get(&format!("{path}{separator}per_page=100&page={page}"))?;
        let values = result
            .as_array()
            .context("remote list missing or redacted")?;
        ensure!(values.len() <= 100, "remote pagination ambiguous");
        items.extend(values.iter().cloned());
        if values.len() < 100 {
            return Ok(items);
        }
    }
    anyhow::bail!("remote pagination incomplete")
}

fn encoded_segment(value: &str) -> String {
    value
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

impl Authority {
    fn load(
        git: &Git,
        api: &impl AuthenticatedRead,
        repository: &str,
        expected_id: &str,
    ) -> Result<Self> {
        let root = format!("/repos/{repository}");
        let remote = api.get(&root)?;
        let repository_id: u64 = expected_id
            .parse()
            .context("enrolled numeric repository identity invalid")?;
        ensure!(
            remote.get("id").and_then(Value::as_u64) == Some(repository_id)
                && string(&remote, "/full_name")? == repository,
            "remote repository identity mismatch"
        );
        ensure!(
            remote.get("private") == Some(&json!(false))
                && string(&remote, "/visibility")? == "public",
            "remote repository is not public"
        );
        let default_branch = string(&remote, "/default_branch")?.to_owned();
        git.read(&["check-ref-format", &format!("refs/heads/{default_branch}")])?;

        let rulesets = pages(api, &format!("{root}/rulesets?includes_parents=true"))?;
        for ruleset in &rulesets {
            ensure!(
                ruleset
                    .get("id")
                    .and_then(Value::as_u64)
                    .is_some_and(|id| id > 0)
                    && !string(ruleset, "/name")?.is_empty(),
                "branch authority list entry missing or malformed"
            );
        }
        let matches: Vec<_> = rulesets
            .iter()
            .filter(|v| v.get("name").and_then(Value::as_str) == Some(AUTHORITY_NAME))
            .collect();
        ensure!(matches.len() == 1, "branch authority missing or ambiguous");
        let id = matches[0]
            .get("id")
            .and_then(Value::as_u64)
            .context("branch authority identity missing")?;
        let authority = api.get(&format!("{root}/rulesets/{id}"))?;
        let expected = json!({
            "name":AUTHORITY_NAME,"target":"branch","enforcement":"active",
            "bypass_actors":[{"actor_id":BOT_APP_ID,"actor_type":"Integration","bypass_mode":"always"}],
            "conditions":{"ref_name":{"include":["~ALL"],"exclude":[]}},
            "rules":[{"type":"creation"},{"type":"update"},{"type":"deletion"},{"type":"non_fast_forward"}]
        });
        ensure!(
            authority.get("id").and_then(Value::as_u64) == Some(id),
            "branch authority identity mismatch"
        );
        for key in [
            "name",
            "target",
            "enforcement",
            "bypass_actors",
            "conditions",
            "rules",
        ] {
            ensure!(
                authority.get(key) == expected.get(key),
                "exact App-only branch authority unavailable"
            );
        }

        let reference = api.get(&format!(
            "{root}/git/ref/heads/{}",
            encoded_segment(&default_branch)
        ))?;
        ensure!(
            string(&reference, "/ref")? == format!("refs/heads/{default_branch}")
                && string(&reference, "/object/type")? == "commit",
            "default branch identity mismatch"
        );
        let published_head = oid(&reference, "/object/sha")?.to_owned();
        ensure!(
            git.resolve(&format!("{published_head}^{{commit}}"))? == published_head,
            "published head object unavailable"
        );
        Ok(Self {
            root,
            repository_id,
            default_branch,
            published_head,
        })
    }

    fn verify_merge(
        &self,
        git: &Git,
        api: &impl AuthenticatedRead,
        repository: &str,
        merge: &str,
        tree: &str,
        parents: &[&str],
    ) -> Result<()> {
        git.read(&["merge-base", "--is-ancestor", merge, &self.published_head])
            .context("merge is not on the authenticated published default branch")?;
        let remote = api.get(&format!("{}/commits/{merge}", self.root))?;
        ensure!(
            oid(&remote, "/sha")? == merge,
            "remote merge identity mismatch"
        );
        ensure!(
            string(&remote, "/author/login")? == BOT_NAME
                && string(&remote, "/commit/author/name")? == BOT_NAME
                && string(&remote, "/commit/author/email")? == BOT_EMAIL,
            "remote merge author is not the exact bot"
        );
        ensure!(
            string(&remote, "/committer/login")? == "web-flow"
                && string(&remote, "/commit/committer/name")? == "GitHub"
                && string(&remote, "/commit/committer/email")? == "noreply@github.com",
            "remote merge committer is not exact GitHub"
        );
        ensure!(
            remote.pointer("/commit/verification/verified") == Some(&json!(true))
                && string(&remote, "/commit/verification/reason")? == "valid",
            "historical merge signature is not verified"
        );
        let remote_parents = remote
            .get("parents")
            .and_then(Value::as_array)
            .context("remote merge parents unavailable")?;
        ensure!(
            remote_parents.len() == 2
                && oid(&remote_parents[0], "/sha")? == parents[0]
                && oid(&remote_parents[1], "/sha")? == parents[1],
            "remote and local merge parents differ"
        );
        ensure!(
            oid(&remote, "/commit/tree/sha")? == tree,
            "remote and local merge trees differ"
        );

        let pulls = pages(api, &format!("{}/commits/{merge}/pulls", self.root))?;
        for pull in &pulls {
            ensure!(
                pull.get("number")
                    .and_then(Value::as_u64)
                    .is_some_and(|number| number > 0)
                    && match pull.get("merge_commit_sha") {
                        // GitHub explicitly represents unmerged associated PRs
                        // with null. A missing discriminator is not that state.
                        Some(Value::Null) => true,
                        Some(Value::String(sha)) => is_oid(sha),
                        _ => false,
                    },
                "associated pull request list entry missing or malformed"
            );
        }
        let matches: Vec<_> = pulls
            .iter()
            .filter(|pr| pr.get("merge_commit_sha").and_then(Value::as_str) == Some(merge))
            .collect();
        ensure!(
            matches.len() == 1,
            "merged pull request missing or ambiguous"
        );
        let number = matches[0]
            .get("number")
            .and_then(Value::as_u64)
            .filter(|n| *n > 0)
            .context("pull request identity unavailable")?;
        let pr = api.get(&format!("{}/pulls/{number}", self.root))?;
        ensure!(
            pr.get("number").and_then(Value::as_u64) == Some(number),
            "pull request identity mismatch"
        );
        ensure!(
            pr.get("merged") == Some(&json!(true))
                && string(&pr, "/state")? == "closed"
                && oid(&pr, "/merge_commit_sha")? == merge,
            "pull request is not this completed merge"
        );
        ensure!(
            string(&pr, "/merged_by/login")? == BOT_NAME,
            "pull request was not merged by the exact bot"
        );
        for side in ["head", "base"] {
            ensure!(
                string(&pr, &format!("/{side}/repo/full_name"))? == repository
                    && pr
                        .pointer(&format!("/{side}/repo/id"))
                        .and_then(Value::as_u64)
                        == Some(self.repository_id),
                "pull request is not same-repository"
            );
        }
        ensure!(
            string(&pr, "/base/ref")? == self.default_branch,
            "pull request target is not the default branch"
        );
        ensure!(
            oid(&pr, "/head/sha")? == parents[1],
            "pull request head is not the second merge parent"
        );
        git.read(&["merge-base", "--is-ancestor", parents[0], parents[1]])
            .context("pull request head did not incorporate its merge basis")?;
        ensure!(
            git.resolve(&format!("{}^{{tree}}", parents[1]))? == tree,
            "merge changed the accepted pull request tree"
        );
        Ok(())
    }
}
