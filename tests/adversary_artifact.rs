use anyhow::Result;
use b10x_gates::{
    artifact, digest,
    git::Unit,
    policy::Policy,
    scan::{SecretFinding, SecretScanner},
};
use std::{collections::BTreeMap, fs};

fn word(bytes: &mut [u8], offset: usize, value: u64, width: usize) {
    bytes[offset..offset + width].copy_from_slice(&value.to_le_bytes()[..width]);
}

fn executable() -> Vec<u8> {
    let data = b"public release metadata\0";
    let names = b"\0.data\0.shstrtab\0";
    let names_offset = 120 + data.len();
    let sections = (names_offset + names.len() + 7) & !7;
    let mut bytes = vec![0; sections + 3 * 64];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    word(&mut bytes, 16, 2, 2);
    word(&mut bytes, 18, 62, 2);
    word(&mut bytes, 20, 1, 4);
    word(&mut bytes, 32, 64, 8);
    word(&mut bytes, 40, sections as u64, 8);
    word(&mut bytes, 52, 64, 2);
    word(&mut bytes, 54, 56, 2);
    word(&mut bytes, 56, 1, 2);
    word(&mut bytes, 58, 64, 2);
    word(&mut bytes, 60, 3, 2);
    word(&mut bytes, 62, 2, 2);
    let size = bytes.len() as u64;
    word(&mut bytes, 64, 1, 4); // PT_LOAD, complete file-backed extent.
    word(&mut bytes, 68, 4, 4);
    word(&mut bytes, 96, size, 8);
    word(&mut bytes, 104, size, 8);
    word(&mut bytes, 112, 1, 8);
    bytes[120..names_offset].copy_from_slice(data);
    bytes[names_offset..names_offset + names.len()].copy_from_slice(names);
    for (index, name, kind, offset, length) in [
        (1, 1, 1, 120, data.len()),
        (2, 7, 3, names_offset, names.len()),
    ] {
        let base = sections + index * 64;
        word(&mut bytes, base, name, 4);
        word(&mut bytes, base + 4, kind, 4);
        word(&mut bytes, base + 24, offset as u64, 8);
        word(&mut bytes, base + 32, length as u64, 8);
        word(&mut bytes, base + 48, 1, 8);
    }
    bytes
}

fn policy() -> Policy {
    Policy {
        version: 1,
        nonce: "synthetic-adversary-artifact-policy".into(),
        forbidden_literals: vec![],
        forbidden_patterns: vec![],
        allow_patterns: vec![],
        repositories: BTreeMap::new(),
        signers: BTreeMap::new(),
        exceptions: vec![],
    }
}

#[derive(Default)]
struct ObservedScanner {
    calls: usize,
    bytes: Vec<u8>,
    fail: bool,
}
impl SecretScanner for ObservedScanner {
    fn scan(&mut self, units: &[Unit]) -> Result<Vec<SecretFinding>> {
        self.calls += 1;
        assert_eq!(units.len(), 1);
        self.bytes = units[0].bytes.clone();
        if self.fail {
            anyhow::bail!("synthetic scanner refusal");
        }
        Ok(vec![])
    }
}

#[test]
fn adversary_all_program_header_ranges_must_be_valid_before_scanning() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("candidate");
    let valid = executable();
    fs::write(&path, &valid).unwrap();
    let mut scanner = ObservedScanner::default();
    artifact::validate(&path, &policy(), &mut scanner).expect("control validates");
    assert_eq!(scanner.calls, 1);
    let mut admitted = Vec::new();
    for kind in [1, 2, 3, 4, 7] {
        // LOAD, DYNAMIC, INTERP, NOTE, TLS.
        let mut bytes = valid.clone();
        word(&mut bytes, 64, kind, 4);
        word(&mut bytes, 72, u64::MAX - 7, 8);
        fs::write(&path, bytes).unwrap();
        let mut scanner = ObservedScanner::default();
        let result = artifact::validate(&path, &policy(), &mut scanner);
        if result.is_ok() || scanner.calls != 0 {
            admitted.push(format!(
                "program type {kind}: accepted={}, scanner_calls={}",
                result.is_ok(),
                scanner.calls
            ));
        }
    }
    assert!(
        admitted.is_empty(),
        "malformed file ranges reached successful scanning: {admitted:?}"
    );
}

#[test]
fn adversary_digest_covers_unscanned_bytes_and_scanner_failure_propagates() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("candidate");
    let mut bytes = executable();
    let mut hashes = Vec::new();
    for byte in [0x80, 0x81] {
        bytes.push(byte); // Nonprintable overlay, outside every section.
        fs::write(&path, &bytes).unwrap();
        let mut scanner = ObservedScanner::default();
        let report = artifact::validate(&path, &policy(), &mut scanner).expect("control validates");
        assert_eq!(report.sha256, digest(&bytes));
        assert_eq!(report.input_bytes, bytes.len());
        assert_eq!(scanner.calls, 1);
        assert!(
            scanner
                .bytes
                .windows(b"public release metadata".len())
                .any(|s| s == b"public release metadata")
        );
        hashes.push(report.sha256);
    }
    assert_ne!(hashes[0], hashes[1]);
    let mut scanner = ObservedScanner {
        fail: true,
        ..ObservedScanner::default()
    };
    let error = artifact::validate(&path, &policy(), &mut scanner)
        .err()
        .expect("scanner refusal propagates");
    assert!(error.to_string().contains("synthetic scanner refusal"));
    assert_eq!(scanner.calls, 1);
}
