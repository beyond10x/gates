//! Small Mach-O and PE executables and zip archives, written byte by byte for the release
//! scan's tests. No real binary of any project is committed; every fixture is built here.
#![allow(dead_code)]

fn le16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
}

fn le32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

fn le64(bytes: &mut [u8], at: usize, value: u64) {
    bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn be32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_be_bytes());
}

pub const MH_OBJECT: u32 = 1;
pub const MH_EXECUTE: u32 = 2;
pub const MH_DYLIB: u32 = 6;
pub const CPU_ARM64: u32 = 0x0100_000c;
pub const CPU_X86_64: u32 = 0x0100_0007;
/// Where the first `section_64` of `macho64` starts: the header, then the segment command.
pub const MACHO_SECTIONS: usize = 32 + 72;
/// The size of one `section_64`; its `size` field is at 40, its `offset` field at 48.
pub const MACHO_SECTION: usize = 80;

/// A thin 64-bit little-endian Mach-O executable for arm64: one `__TEXT` segment holding an
/// instruction section `__text`, a data section `__const` and a zero-fill section `__bss`.
pub fn macho64(text: &[u8], data: &[u8]) -> Vec<u8> {
    macho64_with(MH_EXECUTE, CPU_ARM64, text, data, None)
}

/// As `macho64`, of `filetype` for `cputype`, with an `LC_ENCRYPTION_INFO_64` command whose
/// `cryptid` is `crypt` when that is set.
pub fn macho64_with(
    filetype: u32,
    cputype: u32,
    text: &[u8],
    data: &[u8],
    crypt: Option<u32>,
) -> Vec<u8> {
    const HEADER: usize = 32;
    const SEGMENT: usize = 72;
    const SECTIONS: usize = 3;
    const ENCRYPTION: usize = 24;
    let segment_size = SEGMENT + SECTIONS * MACHO_SECTION;
    let commands = segment_size + if crypt.is_some() { ENCRYPTION } else { 0 };
    let text_at = HEADER + commands;
    let data_at = text_at + text.len();
    let end = data_at + data.len();
    let mut bytes = vec![0u8; end];
    le32(&mut bytes, 0, 0xfeed_facf);
    le32(&mut bytes, 4, cputype);
    le32(&mut bytes, 12, filetype);
    le32(&mut bytes, 16, if crypt.is_some() { 2 } else { 1 });
    le32(&mut bytes, 20, commands as u32);
    // LC_SEGMENT_64 `__TEXT`, mapping the whole file.
    let at = HEADER;
    le32(&mut bytes, at, 0x19);
    le32(&mut bytes, at + 4, segment_size as u32);
    bytes[at + 8..at + 14].copy_from_slice(b"__TEXT");
    le64(&mut bytes, at + 24, 0x1_0000_0000);
    le64(&mut bytes, at + 32, 0x10_0000);
    le64(&mut bytes, at + 40, 0);
    le64(&mut bytes, at + 48, end as u64);
    le32(&mut bytes, at + 56, 5);
    le32(&mut bytes, at + 60, 5);
    le32(&mut bytes, at + 64, SECTIONS as u32);
    let sections: [(&[u8], usize, usize, u32); SECTIONS] = [
        // S_REGULAR | S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
        (b"__text", text_at, text.len(), 0x8000_0400),
        // S_REGULAR
        (b"__const", data_at, data.len(), 0),
        // S_ZEROFILL: no bytes in the file.
        (b"__bss", 0, 64, 1),
    ];
    for (i, (name, offset, size, flags)) in sections.into_iter().enumerate() {
        let at = MACHO_SECTIONS + i * MACHO_SECTION;
        bytes[at..at + name.len()].copy_from_slice(name);
        bytes[at + 16..at + 22].copy_from_slice(b"__TEXT");
        le64(&mut bytes, at + 32, 0x1_0000_0000 + offset as u64);
        le64(&mut bytes, at + 40, size as u64);
        le32(&mut bytes, at + 48, offset as u32);
        le32(&mut bytes, at + 64, flags);
    }
    if let Some(cryptid) = crypt {
        let at = HEADER + segment_size;
        le32(&mut bytes, at, 0x2c);
        le32(&mut bytes, at + 4, ENCRYPTION as u32);
        le32(&mut bytes, at + 8, text_at as u32);
        le32(&mut bytes, at + 12, text.len() as u32);
        le32(&mut bytes, at + 16, cryptid);
    }
    bytes[text_at..data_at].copy_from_slice(text);
    bytes[data_at..end].copy_from_slice(data);
    bytes
}

/// A universal (fat) Mach-O of `slices`, each aligned to 4 KiB, with `gap` written right
/// after the fat header, outside every slice.
pub fn macho_fat(slices: &[Vec<u8>], gap: &[u8]) -> Vec<u8> {
    const ALIGN: usize = 4096;
    let header = 8 + 20 * slices.len();
    let mut bytes = vec![0u8; header];
    be32(&mut bytes, 0, 0xcafe_babe);
    be32(&mut bytes, 4, slices.len() as u32);
    bytes.extend_from_slice(gap);
    for (i, slice) in slices.iter().enumerate() {
        bytes.resize(bytes.len().div_ceil(ALIGN) * ALIGN, 0);
        let offset = bytes.len();
        let cputype = u32::from_le_bytes(slice[4..8].try_into().unwrap());
        let at = 8 + 20 * i;
        be32(&mut bytes, at, cputype);
        be32(&mut bytes, at + 8, offset as u32);
        be32(&mut bytes, at + 12, slice.len() as u32);
        be32(&mut bytes, at + 16, 12);
        bytes.extend_from_slice(slice);
    }
    bytes
}

/// `IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE`
pub const PE_EXECUTABLE: u16 = 0x0022;
/// `IMAGE_FILE_DLL`
pub const PE_DLL: u16 = 0x2000;
const PE_FILE_ALIGNMENT: usize = 0x200;
/// Where the COFF file header of `pe` starts, after the DOS header and the `PE\0\0` signature.
pub const PE_COFF: usize = 0x44;

/// Where the section table of `pe` starts.
pub fn pe_sections(bits64: bool) -> usize {
    PE_COFF + 20 + if bits64 { 240 } else { 224 }
}

/// A PE image (PE32+ for x86-64 when `bits64`, PE32 for i386 otherwise): a `.text` section of
/// code and an `.rdata` section of read-only data.
pub fn pe(bits64: bool, text: &[u8], data: &[u8]) -> Vec<u8> {
    pe_with(bits64, PE_EXECUTABLE, text, data)
}

/// As `pe`, with these COFF `characteristics`.
pub fn pe_with(bits64: bool, characteristics: u16, text: &[u8], data: &[u8]) -> Vec<u8> {
    let optional = if bits64 { 240 } else { 224 };
    let table = pe_sections(bits64);
    let headers = (table + 2 * 40).div_ceil(PE_FILE_ALIGNMENT) * PE_FILE_ALIGNMENT;
    let raw = |len: usize| len.div_ceil(PE_FILE_ALIGNMENT) * PE_FILE_ALIGNMENT;
    let text_at = headers;
    let data_at = text_at + raw(text.len());
    let end = data_at + raw(data.len());
    let mut bytes = vec![0u8; end];
    bytes[..2].copy_from_slice(b"MZ");
    le32(&mut bytes, 0x3c, 0x40);
    bytes[0x40..0x44].copy_from_slice(b"PE\0\0");
    le16(&mut bytes, PE_COFF, if bits64 { 0x8664 } else { 0x14c });
    le16(&mut bytes, PE_COFF + 2, 2);
    le16(&mut bytes, PE_COFF + 16, optional as u16);
    le16(&mut bytes, PE_COFF + 18, characteristics);
    let at = PE_COFF + 20;
    le16(&mut bytes, at, if bits64 { 0x20b } else { 0x10b });
    le32(&mut bytes, at + 4, raw(text.len()) as u32);
    le32(&mut bytes, at + 8, raw(data.len()) as u32);
    le32(&mut bytes, at + 16, 0x1000);
    le32(&mut bytes, at + 20, 0x1000);
    if bits64 {
        le64(&mut bytes, at + 24, 0x1_4000_0000);
    } else {
        le32(&mut bytes, at + 24, 0x2000);
        le32(&mut bytes, at + 28, 0x40_0000);
    }
    le32(&mut bytes, at + 32, 0x1000);
    le32(&mut bytes, at + 36, PE_FILE_ALIGNMENT as u32);
    le16(&mut bytes, at + 40, 6);
    le16(&mut bytes, at + 48, 6);
    le32(&mut bytes, at + 56, 0x3000);
    le32(&mut bytes, at + 60, headers as u32);
    le16(&mut bytes, at + 68, 3);
    le16(&mut bytes, at + 70, 0x8160);
    if bits64 {
        le64(&mut bytes, at + 72, 0x10_0000);
        le64(&mut bytes, at + 80, 0x1000);
        le64(&mut bytes, at + 88, 0x10_0000);
        le64(&mut bytes, at + 96, 0x1000);
        le32(&mut bytes, at + 108, 16);
    } else {
        le32(&mut bytes, at + 72, 0x10_0000);
        le32(&mut bytes, at + 76, 0x1000);
        le32(&mut bytes, at + 80, 0x10_0000);
        le32(&mut bytes, at + 84, 0x1000);
        le32(&mut bytes, at + 92, 16);
    }
    let sections = [
        // IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
        (
            &b".text"[..],
            text_at,
            text.len(),
            raw(text.len()),
            0x1000,
            0x6000_0020,
        ),
        // IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
        (
            b".rdata",
            data_at,
            data.len(),
            raw(data.len()),
            0x2000,
            0x4000_0040,
        ),
    ];
    for (i, (name, offset, size, raw_size, address, flags)) in sections.into_iter().enumerate() {
        let at = table + i * 40;
        bytes[at..at + name.len()].copy_from_slice(name);
        le32(&mut bytes, at + 8, size as u32);
        le32(&mut bytes, at + 12, address);
        le32(&mut bytes, at + 16, raw_size as u32);
        le32(&mut bytes, at + 20, offset as u32);
        le32(&mut bytes, at + 36, flags);
    }
    bytes[text_at..text_at + text.len()].copy_from_slice(text);
    bytes[data_at..data_at + data.len()].copy_from_slice(data);
    bytes
}

/// A COFF object file for x86-64, as a compiler writes one before linking.
pub fn coff_object() -> Vec<u8> {
    let mut bytes = vec![0u8; 20 + 40 + 16];
    le16(&mut bytes, 0, 0x8664);
    le16(&mut bytes, 2, 1);
    bytes[20..25].copy_from_slice(b".text");
    le32(&mut bytes, 20 + 16, 16);
    le32(&mut bytes, 20 + 20, 60);
    le32(&mut bytes, 20 + 36, 0x6000_0020);
    bytes[60..].copy_from_slice(b"safe object text");
    bytes
}

pub const S_IFREG: u32 = 0o100_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFCHR: u32 = 0o020_000;
pub const S_IFIFO: u32 = 0o010_000;
pub const STORED: u16 = 0;
pub const DEFLATED: u16 = 8;

/// The NTFS extra field 7-Zip writes: one record of ID 0x000a, 32 bytes long: four reserved
/// zero bytes, then attribute tag 0x0001 of 24 bytes, the modification, access and creation
/// times as FILETIMEs.
pub fn ntfs_extra(times: [u64; 3]) -> Vec<u8> {
    let mut extra = Vec::with_capacity(36);
    extra.extend(0x000au16.to_le_bytes());
    extra.extend(32u16.to_le_bytes());
    extra.extend(0u32.to_le_bytes());
    extra.extend(0x0001u16.to_le_bytes());
    extra.extend(24u16.to_le_bytes());
    for time in times {
        extra.extend(time.to_le_bytes());
    }
    extra
}

/// FILETIMEs of a build, in 100 ns ticks since 1601.
pub const FILETIMES: [u64; 3] = [
    0x01db_3f4e_7a2c_8000,
    0x01db_3f4e_7a2c_8000,
    0x01db_3f4e_7a2c_8000,
];

/// One zip entry. `central` and `local` change the header each copy is written from, so a
/// case can make them disagree; `crc` and `size` replace the computed values in both.
#[derive(Clone)]
pub struct ZipEntry {
    pub name: Vec<u8>,
    pub data: Vec<u8>,
    pub method: u16,
    pub flags: u16,
    pub mode: u32,
    pub comment: Vec<u8>,
    pub extra: Vec<u8>,
    pub crc: Option<u32>,
    pub size: Option<u32>,
    /// The compressed bytes as written, when a case supplies them itself.
    pub packed: Option<Vec<u8>>,
    pub local_name: Option<Vec<u8>>,
    pub local_method: Option<u16>,
    pub local_crc: Option<u32>,
    pub local_size: Option<u32>,
    /// Bytes written before the local header, which no zip structure describes.
    pub before: Vec<u8>,
    /// The local header's extra field, when it differs from the central one.
    pub local_extra: Option<Vec<u8>>,
    /// The external attributes, when a case sets them itself.
    pub external: Option<u32>,
}

impl ZipEntry {
    /// A regular file, deflated, as `zip -X` writes one.
    pub fn file(name: &str, data: &[u8]) -> Self {
        Self {
            name: name.as_bytes().to_vec(),
            data: data.to_vec(),
            method: DEFLATED,
            flags: 0,
            mode: S_IFREG | 0o644,
            comment: Vec::new(),
            extra: Vec::new(),
            crc: None,
            size: None,
            packed: None,
            local_name: None,
            local_method: None,
            local_crc: None,
            local_size: None,
            before: Vec::new(),
            local_extra: None,
            external: None,
        }
    }

    pub fn stored(name: &str, data: &[u8]) -> Self {
        Self {
            method: STORED,
            ..Self::file(name, data)
        }
    }

    pub fn dir(name: &str) -> Self {
        Self {
            mode: S_IFDIR | 0o755,
            ..Self::stored(name, b"")
        }
    }

    /// As 7-Zip writes an entry: an NTFS extra field of `times` in the central directory and
    /// none in the local header, DOS attributes and no unix mode.
    pub fn seven_zip(mut self, times: [u64; 3]) -> Self {
        let directory = self.name.ends_with(b"/");
        self.extra = ntfs_extra(times);
        self.local_extra = Some(Vec::new());
        self.mode = 0;
        self.external = Some(if directory { 0x10 } else { 0x20 });
        self
    }

    pub fn with(mut self, edit: impl FnOnce(&mut Self)) -> Self {
        edit(&mut self);
        self
    }

    fn packed(&self) -> Vec<u8> {
        if let Some(packed) = &self.packed {
            return packed.clone();
        }
        match self.method {
            DEFLATED => {
                use std::io::Write;
                let mut encoder =
                    flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
                encoder.write_all(&self.data).unwrap();
                encoder.finish().unwrap()
            }
            _ => self.data.clone(),
        }
    }
}

/// A zip archive, written as `zip -q -X -r` writes one: local headers and data, then the
/// central directory, then the end record.
#[derive(Clone, Default)]
pub struct Zip {
    pub entries: Vec<ZipEntry>,
    pub comment: Vec<u8>,
}

impl Zip {
    pub fn entry(mut self, entry: ZipEntry) -> Self {
        self.entries.push(entry);
        self
    }

    pub fn file(self, name: &str, data: &[u8]) -> Self {
        self.entry(ZipEntry::file(name, data))
    }

    pub fn dir(self, name: &str) -> Self {
        self.entry(ZipEntry::dir(name))
    }

    pub fn build(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut central = Vec::new();
        for entry in &self.entries {
            let packed = entry.packed();
            let mut crc = flate2::Crc::new();
            crc.update(&entry.data);
            let crc = entry.crc.unwrap_or(crc.sum());
            let size = entry.size.unwrap_or(entry.data.len() as u32);
            let needed: u16 = if entry.method == DEFLATED || entry.mode & S_IFDIR != 0 {
                20
            } else {
                10
            };
            bytes.extend(&entry.before);
            let offset = bytes.len() as u32;
            let local_name = entry.local_name.as_ref().unwrap_or(&entry.name);
            bytes.extend(0x0403_4b50u32.to_le_bytes());
            bytes.extend(needed.to_le_bytes());
            bytes.extend(entry.flags.to_le_bytes());
            bytes.extend(entry.local_method.unwrap_or(entry.method).to_le_bytes());
            bytes.extend([0x00, 0x60, 0x7b, 0x5b]);
            bytes.extend(entry.local_crc.unwrap_or(crc).to_le_bytes());
            bytes.extend((packed.len() as u32).to_le_bytes());
            bytes.extend(entry.local_size.unwrap_or(size).to_le_bytes());
            bytes.extend((local_name.len() as u16).to_le_bytes());
            let local_extra = entry.local_extra.as_ref().unwrap_or(&entry.extra);
            bytes.extend((local_extra.len() as u16).to_le_bytes());
            bytes.extend(local_name);
            bytes.extend(local_extra);
            bytes.extend(&packed);

            central.extend(0x0201_4b50u32.to_le_bytes());
            central.extend(0x031eu16.to_le_bytes());
            central.extend(needed.to_le_bytes());
            central.extend(entry.flags.to_le_bytes());
            central.extend(entry.method.to_le_bytes());
            central.extend([0x00, 0x60, 0x7b, 0x5b]);
            central.extend(crc.to_le_bytes());
            central.extend((packed.len() as u32).to_le_bytes());
            central.extend(size.to_le_bytes());
            central.extend((entry.name.len() as u16).to_le_bytes());
            central.extend((entry.extra.len() as u16).to_le_bytes());
            central.extend((entry.comment.len() as u16).to_le_bytes());
            central.extend(0u16.to_le_bytes());
            central.extend(0u16.to_le_bytes());
            let dos = if entry.mode & 0o170_000 == S_IFDIR {
                0x10
            } else {
                0
            };
            central.extend(
                entry
                    .external
                    .unwrap_or((entry.mode << 16) | dos)
                    .to_le_bytes(),
            );
            central.extend(offset.to_le_bytes());
            central.extend(&entry.name);
            central.extend(&entry.extra);
            central.extend(&entry.comment);
        }
        let central_at = bytes.len() as u32;
        bytes.extend(&central);
        bytes.extend(0x0605_4b50u32.to_le_bytes());
        bytes.extend(0u16.to_le_bytes());
        bytes.extend(0u16.to_le_bytes());
        bytes.extend((self.entries.len() as u16).to_le_bytes());
        bytes.extend((self.entries.len() as u16).to_le_bytes());
        bytes.extend((central.len() as u32).to_le_bytes());
        bytes.extend(central_at.to_le_bytes());
        bytes.extend((self.comment.len() as u16).to_le_bytes());
        bytes.extend(&self.comment);
        bytes
    }
}
