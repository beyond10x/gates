//! Versioned Ed25519 receipts. Verification never invokes a scanner.
use crate::{
    GITLEAKS_VERSION, VERSION, digest,
    git::{Binding, Candidate},
    policy::{self, Policy},
    scan::{self, RuleResult, SecretScanner},
};
use anyhow::{Context, Result, ensure};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

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
    let public_key = hex::encode(key.verifying_key().to_bytes());
    let signer = policy
        .signers
        .iter()
        .find(|(_, s)| {
            s.public_key == public_key && s.repositories.contains(&candidate.binding.repository)
        })
        .map(|(id, _)| id.clone())
        .context("local signing key is not enrolled for this repository")?;
    let report = scan::run(
        policy,
        &candidate.binding.repository,
        &candidate.units,
        scanner,
    )?;
    report.require_success()?;
    let payload = Payload {
        version: 1,
        binding: candidate.binding.clone(),
        gates_version: VERSION.into(),
        scanner_version: GITLEAKS_VERSION.into(),
        public_policy_digest: public_digest(),
        private_policy_digest: policy.digest()?,
        results: report.results,
        signer,
    };
    let signature = hex::encode(key.sign(&message(&payload)?).to_bytes());
    Ok(Receipt { payload, signature })
}

pub fn verify(policy: &Policy, candidate: &Candidate, receipt: &Receipt) -> Result<()> {
    let p = &receipt.payload;
    ensure!(
        p.version == 1
            && p.gates_version == VERSION
            && p.scanner_version == GITLEAKS_VERSION
            && p.public_policy_digest == public_digest()
            && p.private_policy_digest == policy.digest()?,
        "receipt policy or scanner is stale"
    );
    ensure!(
        p.binding == candidate.binding,
        "receipt repository or exact range mismatch"
    );
    ensure!(
        p.results == scan::expected_results(&candidate.units),
        "receipt results are incomplete or unsuccessful"
    );
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
