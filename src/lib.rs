//! Common security gates. Candidate repositories are read only as Git objects.
pub mod delivery;
pub mod evidence;
pub mod git;
pub mod hooks;
pub mod policy;
pub mod scan;

use sha2::{Digest, Sha256};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const GITLEAKS_VERSION: &str = "8.30.1";
pub const RULES: [&str; 6] = [
    "commit-authorship",
    "secrets",
    "private-identifiers",
    "personal-paths",
    "workflow-pins",
    "workflow-permissions",
];
pub const BOT_NAME: &str = "b10x-bot[bot]";
pub const BOT_EMAIL: &str = "316511680+b10x-bot[bot]@users.noreply.github.com";
pub const ACTIONS_NAME: &str = "github-actions[bot]";
pub const ACTIONS_EMAIL: &str = "41898282+github-actions[bot]@users.noreply.github.com";

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
