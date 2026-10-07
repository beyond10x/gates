//! Adversary case, pass 2 of `story:hex-path-components`: memory `run` holds per
//! line of a unit. One test in its own binary, because it reads the process's peak
//! resident set, which any concurrent test would disturb.
use b10x_gates::{
    git::Unit,
    policy::{Policy, Repository},
    scan::{self, SecretFinding, SecretScanner},
};
use std::{collections::BTreeMap, fs};

const REPOSITORY: &str = "example/repository";
const MIB: usize = 1024 * 1024;

struct NoSecrets;
impl SecretScanner for NoSecrets {
    fn scan(&mut self, _: &[Unit]) -> anyhow::Result<Vec<SecretFinding>> {
        Ok(vec![])
    }
}

fn policy() -> Policy {
    Policy {
        version: 1,
        nonce: "synthetic-policy-nonce-for-local-test-1234".into(),
        forbidden_literals: vec![["synthetic", "restricted", "identifier"].join("-")],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::from([(
            REPOSITORY.into(),
            Repository {
                id: "123".into(),
                baseline: "0".repeat(40),
            },
        )]),
        signers: BTreeMap::new(),
        exceptions: vec![],
    }
}

fn status_kib(field: &str) -> usize {
    fs::read_to_string("/proc/self/status")
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(field))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap()
}

/// Peak resident growth, in bytes, while `run` scans `bytes`.
fn peak_growth(bytes: Vec<u8>) -> usize {
    let u = Unit {
        location: "file:sample".into(),
        bytes,
        workflow: false,
        inherited: None,
    };
    let p = policy();
    // Writing 5 resets the peak resident set to the current one (Linux 4.0+).
    fs::write("/proc/self/clear_refs", "5").unwrap();
    let before = status_kib("VmRSS:");
    let report = scan::run(&p, REPOSITORY, &[u], &mut NoSecrets).unwrap();
    assert!(report.findings.is_empty());
    (status_kib("VmHWM:").saturating_sub(before)) * 1024
}

/// The base code streamed the unit's lines. `run` now collects every line of every
/// non-binary unit into a `Vec<&[u8]>` before the decoded and soft-wrap passes,
/// whether either finds anything or not: 16 bytes per line, so a unit of empty
/// lines costs about 16 times its size (a 128 MiB blob, about 2 GiB).
#[test]
fn adv_run_memory_does_not_grow_with_the_number_of_lines() {
    let size = 4 * MIB;
    // Control: the same size in 4 KiB lines.
    let mut long = Vec::with_capacity(size);
    while long.len() < size {
        long.extend(std::iter::repeat_n(b'x', 4095));
        long.push(b'\n');
    }
    let control = peak_growth(long);
    let empty = peak_growth(vec![b'\n'; size]);
    assert!(
        empty < control + 4 * size,
        "a {} MiB unit of empty lines grew the peak resident set by {} MiB; \
         the same size in 4 KiB lines by {} MiB",
        size / MIB,
        empty / MIB,
        control / MIB
    );
}
