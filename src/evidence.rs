//! Versioned Ed25519 receipts. Verification never invokes a scanner.
use crate::{
    GITLEAKS_VERSION, VERSION, digest,
    git::{Binding, Candidate, Git, Unit},
    policy::{self, Policy},
    scan::{self, RuleResult, SecretScanner},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

const DOMAIN: &[u8] = b"b10x.gates.receipt/1\0";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Payload {
    pub version: u32,
    pub binding: Binding,
    pub gates_version: String,
    pub scanner_version: String,
    pub public_policy_digest: String,
    pub private_policy_digest: String,
    pub results: BTreeMap<String, RuleResult>,
    pub signer: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub payload: Payload,
    pub signature: String,
}

pub fn public_digest() -> String {
    digest(format!("gates/1:{VERSION}:{GITLEAKS_VERSION}:{:?}:git-objects:index:full-changed-blobs:all-outgoing:ignore-suppression:limits-64-256:homes-1:workflows-1:ed25519-1", crate::RULES).as_bytes())
}

fn message(payload: &Payload) -> Result<Vec<u8>> {
    let mut bytes = DOMAIN.to_vec();
    bytes.extend(serde_json::to_vec(payload)?);
    Ok(bytes)
}

pub fn generate_key(path: &Path) -> Result<String> {
    ensure!(!path.exists(), "signing key already exists");
    let key = SigningKey::generate(&mut OsRng);
    policy::private_write(path, hex::encode(key.to_bytes()).as_bytes())?;
    Ok(hex::encode(key.verifying_key().to_bytes()))
}

pub fn read_key(path: &Path) -> Result<SigningKey> {
    let raw = policy::protected_read(path)?;
    let bytes: [u8; 32] = hex::decode(
        std::str::from_utf8(&raw)
            .map_err(|_| anyhow::anyhow!("signing key invalid"))?
            .trim(),
    )
    .map_err(|_| anyhow::anyhow!("signing key invalid"))?
    .try_into()
    .map_err(|_| anyhow::anyhow!("signing key invalid"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn check(
    policy: &Policy,
    candidate: &Candidate,
    key: &SigningKey,
    scanner: &mut dyn SecretScanner,
) -> Result<Receipt> {
    let signer = enrolled(policy, candidate, key)?;
    sign(policy, candidate, key, signer, scanner, &candidate.units)
}

/// The enrolled signer id of the local key for the candidate's repository.
fn enrolled(policy: &Policy, candidate: &Candidate, key: &SigningKey) -> Result<String> {
    let public_key = hex::encode(key.verifying_key().to_bytes());
    policy
        .signers
        .iter()
        .find(|(_, s)| {
            s.public_key == public_key && s.repositories.contains(&candidate.binding.repository)
        })
        .map(|(id, _)| id.clone())
        .context("local signing key is not enrolled for this repository")
}

/// Scan `units` and, when they pass, sign the full statement for `candidate`: the common
/// checks passed for every commit from the baseline to its head. `units` is the whole
/// candidate, or the part of it no verified receipt already covers; in both cases the
/// signed results are what a successful scan of the whole candidate reports.
fn sign(
    policy: &Policy,
    candidate: &Candidate,
    key: &SigningKey,
    signer: String,
    scanner: &mut dyn SecretScanner,
    units: &[Unit],
) -> Result<Receipt> {
    scan::run(policy, &candidate.binding.repository, units, scanner)?.require_success()?;
    let payload = Payload {
        version: 1,
        binding: candidate.binding.clone(),
        gates_version: VERSION.into(),
        scanner_version: GITLEAKS_VERSION.into(),
        public_policy_digest: public_digest(),
        private_policy_digest: policy.digest()?,
        results: scan::expected_results(&candidate.units),
        signer,
    };
    let signature = hex::encode(key.sign(&message(&payload)?).to_bytes());
    Ok(Receipt { payload, signature })
}

pub fn verify(policy: &Policy, candidate: &Candidate, receipt: &Receipt) -> Result<()> {
    current(policy, &receipt.payload)?;
    let p = &receipt.payload;
    ensure!(
        p.binding == candidate.binding,
        "receipt repository or exact range mismatch"
    );
    ensure!(
        p.results == scan::expected_results(&candidate.units),
        "receipt results are incomplete or unsuccessful"
    );
    signed(policy, receipt)
}

/// The receipt was issued by this Gates version and scanner under this exact policy.
fn current(policy: &Policy, p: &Payload) -> Result<()> {
    ensure!(
        p.version == 1
            && p.gates_version == VERSION
            && p.scanner_version == GITLEAKS_VERSION
            && p.public_policy_digest == public_digest()
            && p.private_policy_digest == policy.digest()?,
        "receipt policy or scanner is stale"
    );
    Ok(())
}

/// The receipt is signed by a trusted signer granted the repository it names.
fn signed(policy: &Policy, receipt: &Receipt) -> Result<()> {
    let p = &receipt.payload;
    let signer = policy
        .signers
        .get(&p.signer)
        .context("receipt signer is not trusted")?;
    ensure!(
        signer.repositories.contains(&p.binding.repository),
        "receipt signer has no repository grant"
    );
    let key_bytes: [u8; 32] = hex::decode(&signer.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid trusted key"))?;
    let key = VerifyingKey::from_bytes(&key_bytes)?;
    let signature = Signature::from_slice(&hex::decode(&receipt.signature)?)?;
    key.verify_strict(&message(p)?, &signature)
        .context("receipt signature invalid")?;
    Ok(())
}

/// What `check_reusing` did: the receipt for the candidate, the head of the retained
/// receipt whose coverage it reused, if any, and how many commits it scanned.
pub struct Checked {
    pub receipt: Receipt,
    pub reused: Option<String>,
    pub scanned_commits: usize,
}

/// Sign a receipt for `candidate`, scanning only what no retained receipt already covers.
///
/// A retained receipt that verifies for the exact candidate is returned as is, with zero
/// scanner invocations. Otherwise a retained receipt for an ancestor is reused only when it
/// verifies in full, by `verify`, against the candidate Gates builds for that ancestor's head:
/// signer, repository, baseline, exact commit range, objects, policy, Gates and scanner
/// version. That build takes the commits it shares with this candidate from the units already
/// read, and reads and admits any other commit afresh. The receipt's head must lie in the
/// candidate's own range, so it is an ancestor of the candidate head and not of the baseline.
/// Of those, the one covering the most commits is used; every other commit, merged side
/// branches included, and every tag unit is scanned. With none, the whole candidate is
/// scanned. The signed statement is the same in every case, and a failure never narrows a
/// scan.
pub fn check_reusing(
    policy: &Policy,
    git: &Git,
    candidate: &Candidate,
    retained: &[Receipt],
    key: &SigningKey,
    scanner: &mut dyn SecretScanner,
) -> Result<Checked> {
    let head = &candidate.binding.head;
    if let Some(receipt) = retained
        .iter()
        .find(|r| verify(policy, candidate, r).is_ok())
    {
        return Ok(Checked {
            receipt: receipt.clone(),
            reused: Some(head.clone()),
            scanned_commits: 0,
        });
    }
    let signer = enrolled(policy, candidate, key)?;
    let range: BTreeSet<&str> = candidate
        .binding
        .commits
        .iter()
        .map(String::as_str)
        .collect();
    let mut ancestors: Vec<&Receipt> = retained
        .iter()
        .filter(|r| {
            let b = &r.payload.binding;
            b.tags.is_empty()
                && range.contains(b.head.as_str())
                && current(policy, &r.payload).is_ok()
                && signed(policy, r).is_ok()
        })
        .collect();
    // The claimed range only orders the attempts; each is verified before it counts.
    ancestors.sort_by_key(|r| std::cmp::Reverse(r.payload.binding.commits.len()));
    for receipt in ancestors {
        let ancestor = &receipt.payload.binding.head;
        let Ok(proved) =
            git.candidate_from(policy, &candidate.binding.repository, ancestor, candidate)
        else {
            continue;
        };
        if verify(policy, &proved, receipt).is_err() {
            continue;
        }
        // Verified equal to the range `proved` carries.
        let covered: BTreeSet<&str> = receipt
            .payload
            .binding
            .commits
            .iter()
            .map(String::as_str)
            .collect();
        drop(proved);
        let (units, scanned_commits) = candidate.units_outside(&covered);
        let receipt = sign(policy, candidate, key, signer, scanner, &units)?;
        return Ok(Checked {
            receipt,
            reused: Some(ancestor.clone()),
            scanned_commits,
        });
    }
    Ok(Checked {
        receipt: sign(policy, candidate, key, signer, scanner, &candidate.units)?,
        reused: None,
        scanned_commits: candidate.binding.commits.len(),
    })
}

/// Every parseable `*.receipt.json` in `directory`. Nothing read here is trusted until it
/// verifies; an absent directory holds none.
pub fn retained_in(directory: &Path) -> Vec<Receipt> {
    let Ok(entries) = std::fs::read_dir(directory) else {
        return Vec::new();
    };
    entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.ends_with(".receipt.json"))
                && path.is_file()
        })
        .filter_map(|path| std::fs::read(path).ok())
        .filter_map(|bytes| serde_json::from_slice(&bytes).ok())
        .collect()
}

pub fn reuse_or_scan(
    policy: &Policy,
    candidate: &Candidate,
    receipt: Option<&Receipt>,
    scanner: &mut dyn SecretScanner,
) -> Result<bool> {
    if receipt.is_some_and(|r| verify(policy, candidate, r).is_ok()) {
        return Ok(true);
    }
    scan::run(
        policy,
        &candidate.binding.repository,
        &candidate.units,
        scanner,
    )?
    .require_success()?;
    Ok(false)
}
