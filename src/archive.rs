//! Read a gzip-compressed tar archive in memory, for the scan of a release asset.
//!
//! Nothing is written to disk and nothing is executed. The reader is deliberately narrow and
//! fails closed: one gzip member without an extra field; ustar or GNU headers with valid
//! checksums and octal sizes; GNU long names; the end marker, followed by zero bytes only; at
//! most `max_bytes` unpacked, counted while reading; and at most `MAX_MEMBERS` members. What a
//! member is and what it holds is the caller's to judge.

use anyhow::{Result, anyhow, ensure};
use std::{io::Read, ops::Range};

/// The most members an archive may hold.
pub const MAX_MEMBERS: usize = 10_000;
/// The longest GNU long name, `PATH_MAX`.
pub const MAX_LONG_NAME: usize = 4_096;
const BLOCK: usize = 512;

/// A gzip stream, known by its magic bytes.
pub fn is_gzip(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0x1f, 0x8b])
}

/// An archive, unpacked in memory.
pub struct Archive {
    /// Text published with the archive besides its members, such as the file name and the
    /// comment of a gzip header or the comments of a zip archive: what each is, and its bytes.
    pub notes: Vec<(String, Vec<u8>)>,
    /// The unpacked tar stream, or the unpacked members of a zip archive one after another;
    /// each member's data is a range of it.
    pub data: Vec<u8>,
    pub members: Vec<Member>,
}

/// One member: its whole name, its tar type flag (a zip member's type is given as one) and
/// the range of its data.
pub struct Member {
    pub name: Vec<u8>,
    pub kind: u8,
    pub data: Range<usize>,
}

impl Member {
    pub fn is_file(&self) -> bool {
        matches!(self.kind, b'0' | 0)
    }

    pub fn is_directory(&self) -> bool {
        self.kind == b'5'
    }

    /// An absolute name, or one with a `..` component, names a path outside the archive.
    pub fn escapes(&self) -> bool {
        self.name.starts_with(b"/") || self.name.split(|b| *b == b'/').any(|c| c == b"..")
    }

    /// What the member is, for a refusal.
    pub fn kind_name(&self) -> String {
        match self.kind {
            b'1' => "a hard link".into(),
            b'2' => "a symbolic link".into(),
            b'3' => "a character device".into(),
            b'4' => "a block device".into(),
            b'6' => "a FIFO".into(),
            kind => format!("an entry of type `{}`", kind.escape_ascii()),
        }
    }
}

fn unreadable(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("is a gzip archive the scan cannot read: {reason}")
}

/// Unpack `bytes` in memory. An error completes a sentence whose subject is the asset.
pub fn unpack(bytes: &[u8], max_bytes: u64) -> Result<Archive> {
    let corrupt = || unreadable("the gzip stream is corrupt or cut short");
    let mut decoder = flate2::bufread::GzDecoder::new(bytes);
    let mut data = Vec::new();
    // Bounded while reading: a stream that unpacks to more stops at the bound.
    (&mut decoder)
        .take(max_bytes + 1)
        .read_to_end(&mut data)
        .map_err(|_| corrupt())?;
    if data.len() as u64 > max_bytes {
        return Err(unreadable(format_args!(
            "it unpacks to more than {} MiB, the most the scan reads",
            max_bytes / (1024 * 1024)
        )));
    }
    let header = decoder.header().ok_or_else(corrupt)?;
    ensure!(
        header.extra().is_none(),
        "carries a gzip extra field, which the scan does not read"
    );
    let notes = [
        ("the gzip header's file name", header.filename()),
        ("the gzip header's comment", header.comment()),
    ]
    .into_iter()
    .filter_map(|(what, bytes)| Some((what.to_owned(), bytes?.to_vec())))
    .collect();
    // `MultiGzDecoder` and `gzip -d` read on into a second member; this reader does not.
    if !decoder.into_inner().is_empty() {
        return Err(unreadable("data follows the gzip stream"));
    }
    let members = members(&data)?;
    Ok(Archive {
        notes,
        data,
        members,
    })
}

/// The bytes of a NUL-terminated field, up to its first NUL.
fn field(bytes: &[u8]) -> &[u8] {
    bytes.split(|b| *b == 0).next().unwrap_or_default()
}

/// An octal number: optional leading spaces, octal digits, then only NULs and spaces.
fn octal(bytes: &[u8]) -> Option<u64> {
    let start = bytes.iter().position(|b| *b != b' ')?;
    let digits = &bytes[start..];
    let end = digits
        .iter()
        .position(|b| !(b'0'..=b'7').contains(b))
        .unwrap_or(digits.len());
    if end == 0 || !digits[end..].iter().all(|b| matches!(b, 0 | b' ')) {
        return None;
    }
    digits[..end].iter().try_fold(0u64, |value, digit| {
        value.checked_mul(8)?.checked_add(u64::from(digit - b'0'))
    })
}

fn members(data: &[u8]) -> Result<Vec<Member>> {
    let mut members = Vec::new();
    let mut long: Option<Vec<u8>> = None;
    let mut at = 0;
    loop {
        let number = members.len() + 1;
        let no_member = || {
            unreadable(format_args!(
                "the GNU long name of member {number} names no member"
            ))
        };
        let Some(header) = data.get(at..at + BLOCK) else {
            if long.is_some() {
                return Err(no_member());
            }
            return Err(if at >= data.len() {
                unreadable("the tar stream has no end marker")
            } else {
                unreadable(format_args!("member {number} is cut short"))
            });
        };
        if header.iter().all(|b| *b == 0) {
            if long.is_some() {
                return Err(no_member());
            }
            let Some(second) = data.get(at + BLOCK..at + 2 * BLOCK) else {
                return Err(unreadable("the tar stream has no end marker"));
            };
            if !second
                .iter()
                .chain(&data[at + 2 * BLOCK..])
                .all(|b| *b == 0)
            {
                return Err(unreadable("data follows the tar end marker"));
            }
            return Ok(members);
        }
        let sum: u64 = header
            .iter()
            .enumerate()
            .map(|(i, b)| u64::from(if (148..156).contains(&i) { b' ' } else { *b }))
            .sum();
        if octal(&header[148..156]) != Some(sum) {
            return Err(unreadable(format_args!(
                "the tar header of member {number} is corrupt"
            )));
        }
        let posix = &header[257..265] == b"ustar\x0000";
        if !posix && &header[257..265] != b"ustar  \0" {
            return Err(unreadable(format_args!(
                "the tar header of member {number} is neither ustar nor GNU"
            )));
        }
        let size = octal(&header[124..136]).ok_or_else(|| {
            unreadable(format_args!(
                "the size of member {number} is not an octal number"
            ))
        })?;
        let start = at + BLOCK;
        let end = usize::try_from(size)
            .ok()
            .and_then(|size| start.checked_add(size))
            .filter(|end| *end <= data.len())
            .ok_or_else(|| unreadable(format_args!("member {number} is cut short")))?;
        at = start + (end - start).div_ceil(BLOCK) * BLOCK;
        let kind = header[156];
        if kind == b'L' {
            if long.is_some() {
                return Err(no_member());
            }
            let name = field(&data[start..end]);
            if name.len() > MAX_LONG_NAME {
                return Err(unreadable(format_args!(
                    "the GNU long name of member {number} is longer than {MAX_LONG_NAME} bytes"
                )));
            }
            long = Some(name.to_vec());
            continue;
        }
        let name = match long.take() {
            Some(name) => name,
            None => {
                let name = field(&header[..100]);
                let prefix = field(&header[345..500]);
                if posix && !prefix.is_empty() {
                    [prefix, b"/", name].concat()
                } else {
                    name.to_vec()
                }
            }
        };
        if members.len() == MAX_MEMBERS {
            return Err(unreadable(format_args!(
                "it holds more than {MAX_MEMBERS} members, the most the scan reads"
            )));
        }
        members.push(Member {
            name,
            kind,
            data: start..end,
        });
    }
}
