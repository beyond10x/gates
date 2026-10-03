//! Binary-aware validation for release executables.
//!
//! The supported format is deliberately narrow: ELF64 little-endian executables and dynamic
//! executables with a complete, bounded, uncompressed section inventory. Privacy rules inspect
//! every byte from non-executable sections, while the secret scanner receives their printable
//! runs. Both also receive conventional printable runs of four bytes or more from the complete
//! file. The latter prevents an executable section flag from hiding ordinary identifiers, paths,
//! or secrets while excluding short instruction-byte coincidences. This extraction does not prove
//! that encoded, encrypted, or sub-four-byte executable content carries no private data.

use crate::{
    digest,
    git::Unit,
    policy::Policy,
    scan::{Matchers, SecretScanner},
};
use anyhow::{Context, Result, ensure};
use object::{Object, ObjectKind, ObjectSection, SectionFlags, read::elf::ProgramHeader as _};
use std::{fs::File, io::Read, path::Path};

const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SECTIONS: usize = 4_096;
const MAX_SEGMENTS: usize = 4_096;
const MAX_EXTRACTED_BYTES: usize = 256 * 1024 * 1024;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_COMPRESSED: u64 = 0x800;

/// The successful validation facts safe to publish with a release artifact.
pub struct Report {
    pub sha256: String,
    pub input_bytes: usize,
    pub privacy_bytes: usize,
    pub extracted_bytes: usize,
    pub sections: usize,
}

/// Read, parse, and scan a supported release executable without executing it.
pub fn validate(path: &Path, policy: &Policy, scanner: &mut dyn SecretScanner) -> Result<Report> {
    let bytes = read_bounded(path)?;
    let sha256 = digest(&bytes);
    let (privacy, meaningful, sections) = extract(&bytes)?;
    ensure!(
        !meaningful.is_empty(),
        "artifact carries no meaningful embedded text"
    );

    let matchers = Matchers::build(policy)?;
    let broken = matchers.text(&privacy);
    ensure!(
        broken.is_empty(),
        "artifact breaks {} private rule(s): {}; private details remain local",
        broken.len(),
        broken
            .iter()
            .take(6)
            .map(|(line, rule)| format!("line {line} {rule}"))
            .collect::<Vec<_>>()
            .join(", ")
    );

    let unit = Unit {
        location: "artifact:embedded-text".into(),
        bytes: meaningful,
        workflow: false,
        inherited: None,
    };
    let secrets = scanner.scan(std::slice::from_ref(&unit))?;
    ensure!(
        secrets.is_empty(),
        "artifact breaks secrets rule; private details remain local"
    );

    Ok(Report {
        sha256,
        input_bytes: bytes.len(),
        privacy_bytes: privacy.len(),
        extracted_bytes: unit.bytes.len(),
        sections,
    })
}

fn read_bounded(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).context("artifact unavailable")?;
    let metadata = file.metadata().context("artifact metadata unavailable")?;
    ensure!(metadata.is_file(), "artifact is not a regular file");
    ensure!(
        metadata.len() <= MAX_ARTIFACT_BYTES,
        "artifact exceeds supported size"
    );
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_ARTIFACT_BYTES + 1)
        .read_to_end(&mut bytes)
        .context("artifact read failed")?;
    ensure!(
        bytes.len() as u64 <= MAX_ARTIFACT_BYTES,
        "artifact exceeds supported size"
    );
    Ok(bytes)
}

fn extract(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>, usize)> {
    ensure!(
        bytes.len() >= 16 && &bytes[..4] == b"\x7fELF",
        "artifact format unsupported"
    );
    ensure!(
        bytes[4] == 2 && bytes[5] == 1,
        "artifact format unsupported: expected ELF64 little-endian"
    );
    let file = match object::File::parse(bytes).context("artifact format invalid")? {
        object::File::Elf64(file) => file,
        _ => anyhow::bail!("artifact format unsupported: expected ELF64 little-endian"),
    };
    ensure!(
        matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic),
        "artifact format unsupported: expected ET_EXEC or ET_DYN"
    );

    let sections = file.sections().count();
    ensure!(
        (2..=MAX_SECTIONS).contains(&sections),
        "artifact section inventory invalid"
    );
    let program_headers = file.elf_program_headers();
    ensure!(
        program_headers.len() <= MAX_SEGMENTS,
        "artifact segment inventory invalid"
    );
    for header in program_headers {
        let (offset, size) = header.file_range(file.endian());
        let end = offset
            .checked_add(size)
            .context("artifact segment range invalid")?;
        ensure!(end <= bytes.len() as u64, "artifact segment range invalid");
        header
            .data(file.endian(), bytes)
            .map_err(|()| anyhow::anyhow!("artifact segment range invalid"))?;
    }

    let mut privacy = Vec::new();
    let mut meaningful = Vec::new();
    let mut ranges = Vec::new();
    for section in file.sections() {
        let index = section.index().0;
        let name = section
            .name_bytes()
            .context("artifact section inventory invalid")?;
        let (kind, flags) = match section.flags() {
            SectionFlags::Elf { sh_type, sh_flags } => (sh_type, sh_flags.0),
            _ => anyhow::bail!("artifact section inventory invalid"),
        };
        ensure!(
            flags & SHF_COMPRESSED == 0 && !name.starts_with(b".zdebug_"),
            "compressed artifact sections are unsupported"
        );
        if kind == object::elf::SHT_NOBITS {
            continue;
        } else {
            let data = section
                .data()
                .with_context(|| format!("artifact section range invalid at index {index}"))?;
            match section.file_range() {
                Some((offset, size)) => {
                    let end = offset.checked_add(size).with_context(|| {
                        format!("artifact section range invalid at index {index}")
                    })?;
                    ensure!(
                        end <= bytes.len() as u64 && data.len() as u64 == size,
                        "artifact section range invalid at index {index}"
                    );
                    if size > 0 {
                        ranges.push((offset, end));
                    }
                }
                None => ensure!(
                    section.size() == 0,
                    "artifact section range invalid at index {index}"
                ),
            }
            if flags & SHF_EXECINSTR == 0 {
                raw_section(data, &mut privacy)?;
                printable(data, 1, &mut meaningful)?;
            }
        }
    }
    ranges.sort_unstable();
    ensure!(
        ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0),
        "artifact section ranges overlap"
    );

    // A section marked executable is not enough to exempt ordinary embedded strings.
    printable(bytes, 4, &mut privacy)?;
    printable(bytes, 4, &mut meaningful)?;
    Ok((privacy, meaningful, sections))
}

fn raw_section(bytes: &[u8], output: &mut Vec<u8>) -> Result<()> {
    ensure!(
        output
            .len()
            .checked_add(bytes.len() + 3)
            .is_some_and(|size| size <= MAX_EXTRACTED_BYTES),
        "artifact extracted text exceeds supported size"
    );
    output.extend_from_slice(bytes);
    // A hard boundary prevents adjacent sections from inventing one identifier, including through
    // the matcher's soft-wrap normalization.
    output.extend_from_slice(b"\n\0\n");
    Ok(())
}

fn printable(bytes: &[u8], minimum: usize, output: &mut Vec<u8>) -> Result<()> {
    let mut start = 0;
    while start < bytes.len() {
        while start < bytes.len() && !printable_byte(bytes[start]) {
            start += 1;
        }
        let mut end = start;
        while end < bytes.len() && printable_byte(bytes[end]) {
            end += 1;
        }
        if end.saturating_sub(start) >= minimum {
            ensure!(
                output
                    .len()
                    .checked_add(end - start + 1)
                    .is_some_and(|size| size <= MAX_EXTRACTED_BYTES),
                "artifact extracted text exceeds supported size"
            );
            output.extend_from_slice(&bytes[start..end]);
            output.push(b'\n');
        }
        start = end.saturating_add(1);
    }
    Ok(())
}

fn printable_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t')
}
