//! Binary-aware validation for release executables.
//!
//! The supported formats are deliberately narrow: ELF64 little-endian executables and dynamic
//! executables, thin 64-bit little-endian Mach-O executables and dynamic libraries, Mach-O
//! universal files whose every slice is one of those, and PE32+ or PE32 images, each with a
//! complete, bounded, in-range, non-overlapping and uncompressed section inventory. Privacy
//! rules inspect every byte from non-executable sections, while the secret scanner receives
//! their printable runs. Both also receive conventional printable runs of four bytes or more
//! from the complete file. The latter prevents an executable section flag from hiding ordinary
//! identifiers, paths, or secrets while excluding short instruction-byte coincidences, and it
//! covers bytes outside every section and slice. This extraction does not prove that encoded,
//! encrypted, or sub-four-byte executable content carries no private data.

use crate::{
    digest,
    git::Unit,
    policy::Policy,
    scan::{Matchers, SecretScanner},
};
use anyhow::{Context, Result, ensure};
use object::{
    CompressionFormat, LittleEndian as LE, Object, ObjectKind, ObjectSection, ObjectSegment,
    SectionFlags,
    read::{
        elf::ProgramHeader as _,
        macho::{FatArch, LoadCommandVariant, MachOFatFile32, MachOFatFile64, MachOFile64},
        pe::{ImageNtHeaders, PeFile},
    },
};
use std::{fs::File, io::Read, path::Path};

const MAX_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_SECTIONS: usize = 4_096;
const MAX_SEGMENTS: usize = 4_096;
const MAX_SLICES: usize = 64;
const MAX_EXTRACTED_BYTES: usize = 256 * 1024 * 1024;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_COMPRESSED: u64 = 0x800;
/// glibc's name service switch configuration, which only a glibc that loads NSS modules
/// carries; musl's resolver reads `/etc/hosts` and DNS itself.
const NAME_SERVICE_SWITCH: &[u8] = b"nsswitch.conf";
const MH_MAGIC_64_LE: [u8; 4] = [0xcf, 0xfa, 0xed, 0xfe];

/// Whether `bytes` start with the magic number of a format this module reads: ELF, Mach-O
/// (thin, either byte order and width, or universal) or an MS-DOS header that may lead a PE
/// image. The parser decides what the file is; a file it cannot read is refused.
pub fn is_executable(bytes: &[u8]) -> bool {
    bytes.starts_with(b"\x7fELF")
        || bytes.starts_with(b"MZ")
        || matches!(
            bytes.get(..4),
            Some(
                [0xfe, 0xed, 0xfa, 0xce | 0xcf]
                    | [0xce | 0xcf, 0xfa, 0xed, 0xfe]
                    | [0xca, 0xfe, 0xba, 0xbe | 0xbf]
            )
        )
}

/// The successful validation facts safe to publish with a release artifact.
pub struct Report {
    pub format: &'static str,
    pub sha256: String,
    pub input_bytes: usize,
    pub privacy_bytes: usize,
    pub extracted_bytes: usize,
    pub sections: usize,
}

/// Read, parse, and scan a supported release executable without executing it.
pub fn validate(path: &Path, policy: &Policy, scanner: &mut dyn SecretScanner) -> Result<Report> {
    validate_bytes(&read_bounded(path)?, policy, scanner)
}

/// As `validate`, for an executable already read, such as a member of a release archive.
pub fn validate_bytes(
    bytes: &[u8],
    policy: &Policy,
    scanner: &mut dyn SecretScanner,
) -> Result<Report> {
    let sha256 = digest(bytes);
    let Extracted {
        format,
        privacy,
        meaningful,
        sections,
    } = extract(bytes)?;
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
        format,
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

/// What the scans read of one executable.
struct Extracted {
    format: &'static str,
    privacy: Vec<u8>,
    meaningful: Vec<u8>,
    sections: usize,
}

/// The text of the sections of one file (or of one slice of a universal file), and the file
/// ranges they occupy, which may not overlap.
#[derive(Default)]
struct Sections {
    privacy: Vec<u8>,
    meaningful: Vec<u8>,
    ranges: Vec<(u64, u64)>,
    count: usize,
}

impl Sections {
    /// A section with bytes in the file: its range must lie in the `length` bytes of the file
    /// and hold exactly `data`. A non-executable section's bytes go to both texts.
    fn add(
        &mut self,
        length: usize,
        index: usize,
        range: Option<(u64, u64)>,
        size: u64,
        data: &[u8],
        executable: bool,
    ) -> Result<()> {
        match range {
            Some((offset, size)) => {
                let end = offset
                    .checked_add(size)
                    .with_context(|| format!("artifact section range invalid at index {index}"))?;
                ensure!(
                    end <= length as u64 && data.len() as u64 == size,
                    "artifact section range invalid at index {index}"
                );
                if size > 0 {
                    self.ranges.push((offset, end));
                }
            }
            None => ensure!(
                size == 0 && data.is_empty(),
                "artifact section range invalid at index {index}"
            ),
        }
        if !executable {
            raw_section(data, &mut self.privacy)?;
            printable(data, 1, &mut self.meaningful)?;
        }
        Ok(())
    }

    /// Refuse overlapping section ranges.
    fn check_overlap(&mut self) -> Result<()> {
        self.ranges.sort_unstable();
        ensure!(
            self.ranges.windows(2).all(|pair| pair[0].1 <= pair[1].0),
            "artifact section ranges overlap"
        );
        Ok(())
    }

    /// Append another slice's text, within the bound of what the scans read.
    fn append(&mut self, slice: Sections) -> Result<()> {
        for (output, input) in [
            (&mut self.privacy, slice.privacy),
            (&mut self.meaningful, slice.meaningful),
        ] {
            ensure!(
                output
                    .len()
                    .checked_add(input.len())
                    .is_some_and(|size| size <= MAX_EXTRACTED_BYTES),
                "artifact extracted text exceeds supported size"
            );
            output.extend_from_slice(&input);
        }
        self.count += slice.count;
        Ok(())
    }
}

fn extract(bytes: &[u8]) -> Result<Extracted> {
    let (format, mut sections) = if bytes.starts_with(b"\x7fELF") {
        ("elf64-little-endian", elf(bytes)?)
    } else if bytes.starts_with(b"MZ") {
        pe(bytes)?
    } else if matches!(bytes.get(..4), Some([0xca, 0xfe, 0xba, 0xbe | 0xbf])) {
        ("macho-universal", universal(bytes)?)
    } else if matches!(
        bytes.get(..4),
        Some([0xfe, 0xed, 0xfa, 0xce | 0xcf] | [0xce | 0xcf, 0xfa, 0xed, 0xfe])
    ) {
        ("macho64-little-endian", macho(bytes)?)
    } else {
        anyhow::bail!("artifact format unsupported");
    };

    // A section marked executable is not enough to exempt ordinary embedded strings, and bytes
    // outside every section and slice are read the same way.
    printable(bytes, 4, &mut sections.privacy)?;
    printable(bytes, 4, &mut sections.meaningful)?;
    Ok(Extracted {
        format,
        privacy: sections.privacy,
        meaningful: sections.meaningful,
        sections: sections.count,
    })
}

fn elf(bytes: &[u8]) -> Result<Sections> {
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

    let count = file.sections().count();
    ensure!(
        (2..=MAX_SECTIONS).contains(&count),
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
    // `gates.delivery.ValidateArtifact`, `static-name-service`: a static glibc resolves
    // names by loading the host's `libnss_*` modules, and 0.1.19 faulted on its second
    // GitHub request that way. Refused before any scanner runs.
    let interpreted = program_headers
        .iter()
        .any(|header| header.p_type(file.endian()) == object::elf::PT_INTERP);
    ensure!(
        interpreted || !contains(bytes, NAME_SERVICE_SWITCH),
        "artifact is statically linked against glibc's name service switch, which crashes on \
         name lookups; build the release for x86_64-unknown-linux-musl"
    );

    let mut sections = Sections {
        count,
        ..Sections::default()
    };
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
        }
        let data = section
            .data()
            .with_context(|| format!("artifact section range invalid at index {index}"))?;
        sections.add(
            bytes.len(),
            index,
            section.file_range(),
            section.size(),
            data,
            flags & SHF_EXECINSTR != 0,
        )?;
    }
    sections.check_overlap()?;
    Ok(sections)
}

/// A thin Mach-O file, or one slice of a universal file: 64-bit, little-endian, an executable
/// or a dynamic library, unencrypted, with every segment and section in range.
fn macho(bytes: &[u8]) -> Result<Sections> {
    ensure!(
        bytes.starts_with(&MH_MAGIC_64_LE),
        "artifact format unsupported: expected 64-bit little-endian Mach-O"
    );
    let file =
        MachOFile64::<object::Endianness>::parse(bytes).context("artifact format invalid")?;
    ensure!(
        matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic),
        "artifact format unsupported: expected MH_EXECUTE or MH_DYLIB"
    );
    let endian = file.endian();
    let mut commands = file
        .macho_load_commands()
        .context("artifact format invalid")?;
    while let Some(command) = commands.next().context("artifact format invalid")? {
        let encrypted = match command.variant().context("artifact format invalid")? {
            LoadCommandVariant::EncryptionInfo32(info) => info.cryptid.get(endian) != 0,
            LoadCommandVariant::EncryptionInfo64(info) => info.cryptid.get(endian) != 0,
            _ => false,
        };
        ensure!(!encrypted, "encrypted artifact sections are unsupported");
    }

    let segments = file.segments().count();
    ensure!(
        segments <= MAX_SEGMENTS,
        "artifact segment inventory invalid"
    );
    for segment in file.segments() {
        let (offset, size) = segment.file_range();
        let end = offset
            .checked_add(size)
            .context("artifact segment range invalid")?;
        ensure!(end <= bytes.len() as u64, "artifact segment range invalid");
        segment.data().context("artifact segment range invalid")?;
    }

    let count = file.sections().count();
    ensure!(
        (1..=MAX_SECTIONS).contains(&count),
        "artifact section inventory invalid"
    );
    let mut sections = Sections {
        count,
        ..Sections::default()
    };
    for section in file.sections() {
        let index = section.index().0;
        let name = section
            .name_bytes()
            .context("artifact section inventory invalid")?;
        let flags = match section.flags() {
            SectionFlags::MachO { flags, .. } => flags,
            _ => anyhow::bail!("artifact section inventory invalid"),
        };
        ensure!(
            !name.starts_with(b"__zdebug")
                && section
                    .compressed_file_range()
                    .is_ok_and(|range| range.format == CompressionFormat::None),
            "compressed artifact sections are unsupported"
        );
        if matches!(
            flags.typ(),
            object::macho::S_ZEROFILL
                | object::macho::S_GB_ZEROFILL
                | object::macho::S_THREAD_LOCAL_ZEROFILL
        ) {
            continue;
        }
        let data = section
            .data()
            .with_context(|| format!("artifact section range invalid at index {index}"))?;
        let range = section
            .file_range()
            .with_context(|| format!("artifact section range invalid at index {index}"))?;
        sections.add(
            bytes.len(),
            index,
            Some(range),
            section.size(),
            data,
            flags.intersects(
                object::macho::S_ATTR_PURE_INSTRUCTIONS | object::macho::S_ATTR_SOME_INSTRUCTIONS,
            ),
        )?;
    }
    sections.check_overlap()?;
    Ok(sections)
}

/// A Mach-O universal file: every slice in range, after the slice table, without overlap, and
/// each a thin Mach-O file read as one.
fn universal(bytes: &[u8]) -> Result<Sections> {
    let (table, slices): (u64, Vec<(u64, u64)>) =
        match object::FileKind::parse(bytes).context("artifact format invalid")? {
            object::FileKind::MachOFat32 => {
                let file = MachOFatFile32::parse(bytes).context("artifact format invalid")?;
                (
                    8 + 20 * file.arches().len() as u64,
                    file.arches().iter().map(FatArch::file_range).collect(),
                )
            }
            object::FileKind::MachOFat64 => {
                let file = MachOFatFile64::parse(bytes).context("artifact format invalid")?;
                (
                    8 + 32 * file.arches().len() as u64,
                    file.arches().iter().map(FatArch::file_range).collect(),
                )
            }
            _ => anyhow::bail!("artifact format invalid"),
        };
    ensure!(
        (1..=MAX_SLICES).contains(&slices.len()),
        "artifact slice inventory invalid"
    );
    let mut ranges = Vec::with_capacity(slices.len());
    for (offset, size) in slices {
        let end = offset
            .checked_add(size)
            .context("artifact slice range invalid")?;
        ensure!(
            offset >= table && end <= bytes.len() as u64 && size > 0,
            "artifact slice range invalid"
        );
        ranges.push((offset, end));
    }
    let mut sorted = ranges.clone();
    sorted.sort_unstable();
    ensure!(
        sorted.windows(2).all(|pair| pair[0].1 <= pair[1].0),
        "artifact slice ranges overlap"
    );
    let mut sections = Sections::default();
    for (offset, end) in ranges {
        sections.append(macho(&bytes[offset as usize..end as usize])?)?;
    }
    Ok(sections)
}

/// A PE32+ or PE32 image: an executable or a dynamic library, not an object file.
fn pe(bytes: &[u8]) -> Result<(&'static str, Sections)> {
    Ok(
        match object::File::parse(bytes).context("artifact format invalid")? {
            object::File::Pe64(file) => ("pe32+", pe_sections(bytes, &file)?),
            object::File::Pe32(file) => ("pe32", pe_sections(bytes, &file)?),
            _ => anyhow::bail!("artifact format unsupported: expected a PE32+ or PE32 image"),
        },
    )
}

fn pe_sections<Pe: ImageNtHeaders>(bytes: &[u8], file: &PeFile<'_, Pe>) -> Result<Sections> {
    let characteristics = file.nt_headers().file_header().characteristics.get(LE).0;
    ensure!(
        characteristics & object::pe::IMAGE_FILE_EXECUTABLE_IMAGE.0 != 0
            && matches!(file.kind(), ObjectKind::Executable | ObjectKind::Dynamic),
        "artifact format unsupported: expected a PE executable image"
    );
    let count = file.sections().count();
    ensure!(
        (1..=MAX_SECTIONS).contains(&count),
        "artifact section inventory invalid"
    );
    let mut sections = Sections {
        count,
        ..Sections::default()
    };
    for section in file.sections() {
        let index = section.index().0;
        let name = section
            .name_bytes()
            .context("artifact section inventory invalid")?;
        ensure!(
            !name.starts_with(b".zdebug"),
            "compressed artifact sections are unsupported"
        );
        let header = section.pe_section();
        let flags = header.characteristics.get(LE).0;
        // Every raw byte of the section, file alignment padding included, is read; the
        // virtual size does not shorten what the scans see.
        let offset = u64::from(header.pointer_to_raw_data.get(LE));
        let size = u64::from(header.size_of_raw_data.get(LE));
        if size == 0 {
            continue;
        }
        let data = offset
            .checked_add(size)
            .filter(|end| *end <= bytes.len() as u64)
            .map(|end| &bytes[offset as usize..end as usize])
            .with_context(|| format!("artifact section range invalid at index {index}"))?;
        sections.add(
            bytes.len(),
            index,
            Some((offset, size)),
            size,
            data,
            flags & (object::pe::IMAGE_SCN_MEM_EXECUTE.0 | object::pe::IMAGE_SCN_CNT_CODE.0) != 0,
        )?;
    }
    sections.check_overlap()?;
    Ok(sections)
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn printable_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() || matches!(byte, b' ' | b'\t')
}
