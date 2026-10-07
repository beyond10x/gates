//! Authenticated authority for historical GitHub App merges in delivery ancestry.
//!
//! A public repository proves App-only writes through its branch ruleset. A private repository
//! on a plan without rulesets proves each merge through its pull-request record instead: opened
//! and merged by the exact bot account, two parents only. On either, a two-parent merge's tree
//! must be Git's own clean merge of its parents, recomputed locally.
use crate::{
    BOT_EMAIL, BOT_NAME,
    git::{Git, exact_identity, is_oid, unique_header},
    policy::{Policy, valid_repository},
};
use anyhow::{Context, Result, bail, ensure};
use serde_json::{Value, json};

const BOT_APP_ID: u64 = 4_579_525;
/// The numeric account behind `BOT_NAME`; `BOT_EMAIL` carries the same number.
const BOT_USER_ID: u64 = 316_511_680;
const AUTHORITY_NAME: &str = "b10x-bot-branch-authority";

/// Read evidence from the authenticated GitHub API. Production uses `Github`;
/// tests inject evidence without introducing a configurable production endpoint.
pub trait AuthenticatedRead {
    fn get(&self, path: &str) -> Result<Value>;
}

/// Which proof the authenticated repository visibility selects. It is never chosen by which
/// evidence happens to answer: a public repository without its branch authority refuses.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Visibility {
    /// The App-only branch ruleset proves only the App can write any branch.
    Public,
    /// No ruleset is available on the plan. Each pull request must instead be opened and merged
    /// by the exact bot account, and only two-parent merges are admitted, so every head commit
    /// stays inside the walked ancestry.
    Private,
}

struct Authority {
    root: String,
    repository_id: u64,
    default_branch: String,
    published_head: String,
    visibility: Visibility,
}

struct GithubCommit {
    tree: String,
    parents: Vec<String>,
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
        let commit = github_commit(git, oid)?;
        if authority.is_none() {
            authority = Some(Authority::load(git, api, repository, &enrolled.id)?);
        }
        authority
            .as_ref()
            .context("remote authority unavailable")?
            .verify_github_commit(git, api, repository, oid, &commit)?;
    }
    Ok(())
}

fn github_commit(git: &Git, oid: &str) -> Result<GithubCommit> {
    ensure!(
        git.resolve(&format!("{oid}^{{commit}}"))? == oid,
        "historical GitHub object is not this commit"
    );
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
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    // Two parents is an ordinary pull-request merge; one is a squash merge, which GitHub
    // writes as a single commit over the base. Both are shapes the button produces, and a
    // repository that has taken one cannot deliver again until the shape is admitted — the
    // check below proves each on its own terms rather than treating the squash as a merge.
    ensure!(
        (1..=2).contains(&parents.len()) && parents.iter().all(|p| is_oid(p)),
        "historical merge must have one or two parents"
    );
    let tree = std::str::from_utf8(unique_header(&raw, b"tree ")?)?.to_owned();
    ensure!(is_oid(&tree), "historical merge tree invalid");
    git.read(&["cat-file", "-e", &format!("{tree}^{{tree}}")])?;
    for parent in &parents {
        ensure!(
            git.resolve(&format!("{parent}^{{commit}}"))? == *parent,
            "historical merge parent object unavailable"
        );
        let parent_tree = git.resolve(&format!("{parent}^{{tree}}"))?;
        ensure!(is_oid(&parent_tree), "historical merge parent tree invalid");
        git.read(&["cat-file", "-e", &format!("{parent_tree}^{{tree}}")])?;
    }
    Ok(GithubCommit { tree, parents })
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

fn bot_account(value: &Value, pointer: &str) -> bool {
    value.pointer(pointer).is_some_and(|account| {
        account.get("login").and_then(Value::as_str) == Some(BOT_NAME)
            && account.get("type").and_then(Value::as_str) == Some("Bot")
            && account.get("id").and_then(Value::as_u64) == Some(BOT_USER_ID)
    })
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
        let visibility = match (
            remote.get("private"),
            remote.get("visibility").and_then(Value::as_str),
        ) {
            (Some(Value::Bool(false)), Some("public")) => Visibility::Public,
            (Some(Value::Bool(true)), Some("private")) => Visibility::Private,
            _ => bail!("remote repository visibility is contradictory or unsupported"),
        };
        let default_branch = string(&remote, "/default_branch")?.to_owned();
        git.read(&["check-ref-format", &format!("refs/heads/{default_branch}")])?;

        if visibility == Visibility::Public {
            verify_branch_authority(api, &root)?;
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
            visibility,
        })
    }
}

fn verify_branch_authority(api: &impl AuthenticatedRead, root: &str) -> Result<()> {
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
    Ok(())
}

impl Authority {
    fn verify_github_commit(
        &self,
        git: &Git,
        api: &impl AuthenticatedRead,
        repository: &str,
        oid: &str,
        commit: &GithubCommit,
    ) -> Result<()> {
        self.ensure_published(git, oid)?;
        self.verify_remote_commit(api, oid, commit)?;
        let pulls = self.pull_associations(api, oid)?;
        let terminal = pulls
            .iter()
            .filter(|pr| pr.get("merge_commit_sha").and_then(Value::as_str) == Some(oid))
            .count();
        if terminal > 0 {
            ensure!(terminal == 1, "merged pull request missing or ambiguous");
            return self
                .verify_terminal_merge(git, api, repository, oid, commit, &pulls, None, false);
        }
        self.verify_update_branch(git, api, repository, oid, commit, &pulls)
    }

    fn ensure_published(&self, git: &Git, oid: &str) -> Result<()> {
        git.read(&["merge-base", "--is-ancestor", oid, &self.published_head])
            .context("merge is not on the authenticated published default branch")?;
        Ok(())
    }

    fn verify_remote_commit(
        &self,
        api: &impl AuthenticatedRead,
        commit_oid: &str,
        commit: &GithubCommit,
    ) -> Result<()> {
        let remote = api.get(&format!("{}/commits/{commit_oid}", self.root))?;
        ensure!(
            oid(&remote, "/sha")? == commit_oid,
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
            remote_parents.len() == commit.parents.len()
                && remote_parents.iter().zip(&commit.parents).try_fold(
                    true,
                    |ok, (remote, local)| {
                        Ok::<_, anyhow::Error>(ok && oid(remote, "/sha")? == local)
                    }
                )?,
            "remote and local merge parents differ"
        );
        ensure!(
            oid(&remote, "/commit/tree/sha")? == commit.tree,
            "remote and local merge trees differ"
        );
        Ok(())
    }

    fn pull_associations(&self, api: &impl AuthenticatedRead, oid: &str) -> Result<Vec<Value>> {
        let pulls = pages(api, &format!("{}/commits/{oid}/pulls", self.root))?;
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
        Ok(pulls)
    }

    fn verify_update_branch(
        &self,
        git: &Git,
        api: &impl AuthenticatedRead,
        repository: &str,
        update: &str,
        update_commit: &GithubCommit,
        pulls: &[Value],
    ) -> Result<()> {
        ensure!(
            update_commit.parents.len() == 2
                && update_commit.parents[0] != update_commit.parents[1],
            "branch update must have distinct ordered head and base parents"
        );
        let completed: Vec<_> = pulls
            .iter()
            .filter(|pr| pr.get("merge_commit_sha").and_then(Value::as_str).is_some())
            .collect();
        ensure!(
            completed.len() == 1,
            "updated pull request missing or ambiguous"
        );
        let summary = completed[0];
        let number = summary
            .get("number")
            .and_then(Value::as_u64)
            .filter(|number| *number > 0)
            .context("pull request identity unavailable")?;
        let merge = oid(summary, "/merge_commit_sha")?;
        ensure!(merge != update, "branch update cannot be its final merge");
        self.ensure_same_repository(summary, repository)?;
        ensure!(
            string(summary, "/base/ref")? == self.default_branch,
            "updated pull request summary does not bind this accepted head"
        );
        let head = oid(summary, "/head/sha")?;
        if head != update {
            return self.verify_earlier_update(
                git,
                api,
                repository,
                update,
                update_commit,
                number,
                merge,
                head,
            );
        }
        let pull = self.completed_pull_request(api, repository, number, merge)?;
        ensure!(
            oid(&pull, "/head/sha")? == update,
            "pull request head is not the authenticated branch update"
        );

        let merge_commit = github_commit(git, merge)?;
        ensure!(
            merge_commit.parents.len() == 2
                && merge_commit.parents[0] == update_commit.parents[1]
                && merge_commit.parents[1] == update,
            "final merge parents are not the update base and accepted head"
        );
        ensure!(
            merge_commit.tree == update_commit.tree
                && git.resolve(&format!("{update}^{{tree}}"))? == update_commit.tree,
            "final merge did not preserve the accepted update tree"
        );
        // The final merge's local merge of (base, update) is trivially the update's tree, so the
        // update's own merge of (prior head, base) is recomputed here: it adds nothing of its own
        // only if Git merges those parents cleanly into exactly its tree.
        let local = git.merge_tree(&update_commit.parents[0], &update_commit.parents[1])?;
        ensure!(
            local.clean,
            "local merge of the branch update's parents conflicts"
        );
        ensure!(
            local.tree == update_commit.tree,
            "branch update tree is not the local merge of its parents"
        );
        self.ensure_published(git, merge)?;
        self.verify_remote_commit(api, merge, &merge_commit)?;
        let merge_pulls = self.pull_associations(api, merge)?;
        self.verify_terminal_merge(
            git,
            api,
            repository,
            merge,
            &merge_commit,
            &merge_pulls,
            Some(number),
            true,
        )
    }

    /// An update that is not the pull request's final head: GitHub updated the branch again, or
    /// the bot pushed on top, before the merge. The update must lie on the first-parent line of
    /// the authenticated head, and every commit after it on that line must be the bot's own or
    /// another GitHub update of this same pull request. Each of those commits is still proved on
    /// its own by the delivery walk; this binds the update to the pull request and exempts
    /// nothing. The final merge is then proved as for an update that is the final head.
    #[allow(clippy::too_many_arguments)]
    fn verify_earlier_update(
        &self,
        git: &Git,
        api: &impl AuthenticatedRead,
        repository: &str,
        update: &str,
        update_commit: &GithubCommit,
        number: u64,
        merge: &str,
        head: &str,
    ) -> Result<()> {
        let pull = self.completed_pull_request(api, repository, number, merge)?;
        ensure!(
            oid(&pull, "/head/sha")? == head,
            "pull request head is not the summary's head"
        );
        ensure!(
            git.resolve(&format!("{head}^{{commit}}"))? == head,
            "pull request head object unavailable"
        );
        self.verify_head_line(git, api, update, head, number, merge)?;
        let local = git.merge_tree(&update_commit.parents[0], &update_commit.parents[1])?;
        ensure!(
            local.clean,
            "local merge of the branch update's parents conflicts"
        );
        ensure!(
            local.tree == update_commit.tree,
            "branch update tree is not the local merge of its parents"
        );

        let merge_commit = github_commit(git, merge)?;
        ensure!(
            merge_commit.parents.len() == 2
                && merge_commit.parents[1] == head
                && merge_commit.parents[0] != head,
            "final merge parents are not a base and the pull request head"
        );
        self.ensure_published(git, merge)?;
        self.verify_remote_commit(api, merge, &merge_commit)?;
        let merge_pulls = self.pull_associations(api, merge)?;
        self.verify_terminal_merge(
            git,
            api,
            repository,
            merge,
            &merge_commit,
            &merge_pulls,
            Some(number),
            true,
        )
    }

    /// Following first parents from `head` must reach `update`, and every commit after `update`
    /// up to and including `head` must be an exact direct-bot commit or a GitHub update (exact bot
    /// author, exact GitHub committer, two distinct parents) whose only completed pull request is
    /// this one.
    fn verify_head_line(
        &self,
        git: &Git,
        api: &impl AuthenticatedRead,
        update: &str,
        head: &str,
        number: u64,
        merge: &str,
    ) -> Result<()> {
        // The first-parent walk from the head stops at the first commit reachable from the update.
        // When the update is on that line, that commit is the update itself, so the last commit
        // listed has it as its first parent; when it is not, the walk stops somewhere else.
        let listed = git.text(&["rev-list", "--first-parent", &format!("{update}..{head}")])?;
        let line: Vec<&str> = listed.lines().collect();
        ensure!(
            line.iter().all(|commit| is_oid(commit)),
            "invalid ancestry object"
        );
        let last = line
            .last()
            .context("branch update is not on the first-parent line of the pull request head")?;
        ensure!(
            git.resolve(&format!("{last}^1"))? == update,
            "branch update is not on the first-parent line of the pull request head"
        );
        for commit in line {
            if git.verify_bot(&[commit.to_owned()]).is_ok() {
                continue;
            }
            let shape = github_commit(git, commit).context(
                "a commit on the pull request head line is neither the bot's nor a branch update",
            )?;
            ensure!(
                shape.parents.len() == 2 && shape.parents[0] != shape.parents[1],
                "a commit on the pull request head line is neither the bot's nor a branch update"
            );
            let pulls = self.pull_associations(api, commit)?;
            let completed: Vec<_> = pulls
                .iter()
                .filter(|pr| pr.get("merge_commit_sha").and_then(Value::as_str).is_some())
                .collect();
            ensure!(
                completed.len() == 1
                    && completed[0].get("number").and_then(Value::as_u64) == Some(number)
                    && oid(completed[0], "/merge_commit_sha")? == merge,
                "a branch update on the pull request head line belongs to another pull request"
            );
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_terminal_merge(
        &self,
        git: &Git,
        api: &impl AuthenticatedRead,
        repository: &str,
        merge: &str,
        commit: &GithubCommit,
        pulls: &[Value],
        expected_number: Option<u64>,
        ordinary_only: bool,
    ) -> Result<()> {
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
        if let Some(expected) = expected_number {
            ensure!(
                pulls
                    .iter()
                    .filter(|pull| {
                        pull.get("merge_commit_sha")
                            .and_then(Value::as_str)
                            .is_some()
                    })
                    .count()
                    == 1,
                "final merge association is ambiguous"
            );
            ensure!(
                number == expected,
                "final merge is tied to another pull request"
            );
            self.ensure_same_repository(matches[0], repository)?;
            ensure!(
                string(matches[0], "/base/ref")? == self.default_branch
                    && oid(matches[0], "/head/sha")? == commit.parents[1],
                "final merge summary does not bind the accepted head"
            );
        }
        let pr = self.completed_pull_request(api, repository, number, merge)?;
        if ordinary_only {
            ensure!(
                commit.parents.len() == 2,
                "final update merge must be an ordinary merge"
            );
        }
        if commit.parents.len() == 2 {
            ensure!(
                oid(&pr, "/head/sha")? == commit.parents[1],
                "pull request head is not the second merge parent"
            );
            // Both parents are proved on their own: the base is walked ancestry, and every head
            // commit carries the exact bot identity. The merge adds nothing of its own only if
            // its tree is what Git merges from those two parents, so recompute that merge here
            // rather than trust GitHub's. When the head already contains the base, the merge is
            // the head's tree; when the base moved on after the head was cut, it carries both.
            // A conflicted merge was resolved by somebody, so it refuses even when its tree is
            // the very one Git wrote with the conflict in it.
            let local = git.merge_tree(&commit.parents[0], &commit.parents[1])?;
            ensure!(
                local.clean,
                "local merge of the pull request base and head conflicts"
            );
            ensure!(
                local.tree == commit.tree,
                "merge tree is not the local merge of its base and pull request head"
            );
            return Ok(());
        }
        // A squash merge keeps no reference to the head it accepted, so the tree equality above
        // cannot be asked of it: GitHub composed this tree from the pull request rather than
        // adopting the head's. What remains provable is that the single parent is the base this
        // pull request was merged onto, and that GitHub itself produced the commit from that
        // pull request — the verified signature, the exact bot author, `merged_by`, and
        // `merge_commit_sha` already establish the last of those, above.
        //
        // This is weaker than the two-parent proof by exactly one property: the reviewed tree is
        // not re-derived locally. Admitted deliberately, because a repository whose default
        // branch has taken one squash merge can otherwise never deliver again.
        //
        // It rests on the branch authority: the squashed head commits are outside the walked
        // ancestry, and only the ruleset proves the App alone wrote them. A private repository
        // has no ruleset, so nothing proves who wrote that head, and the shape is refused there.
        ensure!(
            self.visibility == Visibility::Public,
            "private repository admits only two-parent pull-request merges"
        );
        ensure!(
            oid(&pr, "/base/sha")? == commit.parents[0],
            "squash merge parent is not the pull request base"
        );
        git.read(&["merge-base", "--is-ancestor", &commit.parents[0], merge])
            .context("squash merge does not descend from its pull request base")?;
        Ok(())
    }

    fn completed_pull_request(
        &self,
        api: &impl AuthenticatedRead,
        repository: &str,
        number: u64,
        merge: &str,
    ) -> Result<Value> {
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
        if self.visibility == Visibility::Private {
            // Without a ruleset, the merge record is the authority. The `[bot]` login suffix is
            // reserved for Apps; the type and numeric id bind it to this account, not to a
            // reused name.
            ensure!(
                bot_account(&pr, "/merged_by"),
                "pull request was not merged by the exact bot account"
            );
            ensure!(
                bot_account(&pr, "/user"),
                "pull request was not opened by the exact bot account"
            );
        }
        self.ensure_same_repository(&pr, repository)?;
        ensure!(
            string(&pr, "/base/ref")? == self.default_branch,
            "pull request target is not the default branch"
        );
        Ok(pr)
    }

    fn ensure_same_repository(&self, pr: &Value, repository: &str) -> Result<()> {
        for side in ["head", "base"] {
            ensure!(
                string(pr, &format!("/{side}/repo/full_name"))? == repository
                    && pr
                        .pointer(&format!("/{side}/repo/id"))
                        .and_then(Value::as_u64)
                        == Some(self.repository_id),
                "pull request is not same-repository"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn bot_user_id_is_the_account_in_the_bot_email() {
        assert!(
            crate::BOT_EMAIL.starts_with(&format!("{}+", super::BOT_USER_ID)),
            "BOT_USER_ID and BOT_EMAIL name different accounts"
        );
    }
}
