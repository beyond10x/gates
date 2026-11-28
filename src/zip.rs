//! Read a zip archive in memory, for the scan of a release asset.
//!
//! Nothing is written to disk and nothing is executed. The reader is deliberately narrow and
//! fails closed: the archive `zip -X` or 7-Zip writes and little else. One end of central
//! directory record, found at exactly one place; one disk; no zip64; no encryption; no data
//! descriptors; no extra field but the NTFS record 7-Zip writes, whose bytes go to the private
//! rules; members stored or deflated; every local header agreeing with its central directory
//! entry and carrying no extra field or the same one; every byte of the file part of a local
//! header and its data, the central directory or the end record, so no member overlaps
//! another; each member's size and CRC-32 checked; at most `max_bytes` unpacked, counted while
//! reading; and at most `archive::MAX_MEMBERS` members. A member's type comes from the unix
//! mode of its external attributes, or, without one, from a trailing `/`. What a member is and
//! what it holds is the caller's to judge, as for a tar archive.

use crate::archive::{Archive, MAX_MEMBERS, Member};
use anyhow::{Result, anyhow};
use std::io::Read;

const LOCAL: usize = 30;
const CENTRAL: usize = 46;
const END: usize = 22;
const LOCAL_SIGNATURE: u32 = 0x0403_4b50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4b50;
const END_SIGNATURE: u32 = 0x0605_4b50;
/// Traditional encryption, strong encryption and an encrypted central directory.
const ENCRYPTED: u16 = 0x0001 | 0x0040 | 0x2000;
/// The deflate options (bits 1 and 2) and UTF-8 names (bit 11); every other flag is refused.
const KNOWN_FLAGS: u16 = 0x0002 | 0x0004 | 0x0800;
const STORED: u16 = 0;
const DEFLATED: u16 = 8;
/// The length of the data of the NTFS extra field record.
const NTFS: usize = 32;

/// A zip archive, known by the signature of its first local header, or of its end record
/// when it holds no member.
pub fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06")
}

fn unreadable(reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("is a zip archive the scan cannot read: {reason}")
}

/// The one extra field read: an NTFS record (ID 0x000a) as 7-Zip writes it, 32 bytes long, of
/// four reserved zero bytes and attribute tag 0x0001 holding 24 bytes, three FILETIMEs. Any other
/// layout, ID or second record is refused.
fn is_ntfs(extra: &[u8]) -> bool {
    extra.len() == 4 + NTFS
        && u16_at(extra, 0) == 0x000a
        && usize::from(u16_at(extra, 2)) == NTFS
        && u32_at(extra, 4) == 0
        && u16_at(extra, 8) == 0x0001
        && u16_at(extra, 10) == 24
}

fn u16_at(bytes: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([bytes[at], bytes[at + 1]])
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

/// One central directory entry.
struct Entry {
    needed: u16,
    flags: u16,
    method: u16,
    crc: u32,
    packed: u32,
    size: u32,
    name: Vec<u8>,
    kind: u8,
    local: usize,
    extra: Vec<u8>,
}

/// Unpack `bytes` in memory. An error completes a sentence whose subject is the asset.
pub fn unpack(bytes: &[u8], max_bytes: u64) -> Result<Archive> {
    let end = end_record(bytes)?;
    let disk = u16_at(bytes, end + 4);
    let central_disk = u16_at(bytes, end + 6);
    let on_disk = u16_at(bytes, end + 8);
    let total = u16_at(bytes, end + 10);
    let central_size = u32_at(bytes, end + 12);
    let central_at = u32_at(bytes, end + 16);
    if [disk, central_disk, on_disk, total].contains(&u16::MAX)
        || [central_size, central_at].contains(&u32::MAX)
    {
        return Err(unreadable("it is a zip64 archive"));
    }
    if disk != 0 || central_disk != 0 || on_disk != total {
        return Err(unreadable("it spans several disks"));
    }
    if usize::from(total) > MAX_MEMBERS {
        return Err(unreadable(format_args!(
            "it holds more than {MAX_MEMBERS} members, the most the scan reads"
        )));
    }
    let central_at = central_at as usize;
    let mismatch = || unreadable("the central directory does not match the end record");
    if central_at.checked_add(central_size as usize) != Some(end) {
        return Err(mismatch());
    }

    let mut notes = Vec::new();
    if bytes.len() > end + END {
        notes.push((
            "the zip archive's comment".to_owned(),
            bytes[end + END..].to_vec(),
        ));
    }
    let mut entries = Vec::with_capacity(usize::from(total));
    let mut at = central_at;
    for k in 1..=usize::from(total) {
        if at + CENTRAL > end || u32_at(bytes, at) != CENTRAL_SIGNATURE {
            return Err(mismatch());
        }
        let flags = u16_at(bytes, at + 8);
        let method = u16_at(bytes, at + 10);
        let packed = u32_at(bytes, at + 20);
        let size = u32_at(bytes, at + 24);
        let name_length = usize::from(u16_at(bytes, at + 28));
        let extra_length = usize::from(u16_at(bytes, at + 30));
        let comment_length = usize::from(u16_at(bytes, at + 32));
        let local = u32_at(bytes, at + 42);
        let name_at = at + CENTRAL;
        let comment_at = name_at + name_length + extra_length;
        let next = comment_at + comment_length;
        if next > end {
            return Err(mismatch());
        }
        if flags & ENCRYPTED != 0 {
            return Err(unreadable(format_args!("member {k} is encrypted")));
        }
        if flags & !KNOWN_FLAGS != 0 {
            return Err(unreadable(format_args!(
                "member {k} sets general purpose flags the scan does not read"
            )));
        }
        if method != STORED && method != DEFLATED {
            return Err(unreadable(format_args!(
                "member {k} uses compression method {method}, which the scan does not read"
            )));
        }
        let extra = bytes[name_at + name_length..comment_at].to_vec();
        if !extra.is_empty() && !is_ntfs(&extra) {
            return Err(unreadable(format_args!(
                "member {k} carries an extra field, which the scan does not read"
            )));
        }
        if u16_at(bytes, at + 34) != 0 {
            return Err(unreadable("it spans several disks"));
        }
        if [packed, size, local].contains(&u32::MAX) {
            return Err(unreadable("it is a zip64 archive"));
        }
        let name = bytes[name_at..name_at + name_length].to_vec();
        if name.contains(&b'\\') {
            return Err(unreadable(format_args!(
                "the name of member {k} has a backslash"
            )));
        }
        let directory = name.ends_with(b"/");
        let disagree = || unreadable(format_args!("the name and the type of member {k} disagree"));
        let kind = match (u32_at(bytes, at + 38) >> 16) & 0o170_000 {
            0 if directory => b'5',
            0 => b'0',
            0o100_000 if !directory => b'0',
            0o040_000 if directory => b'5',
            0o100_000 | 0o040_000 => return Err(disagree()),
            0o120_000 => b'2',
            0o020_000 => b'3',
            0o060_000 => b'4',
            0o010_000 => b'6',
            _ => b'?',
        };
        if !extra.is_empty() {
            notes.push((format!("the extra field of member {k}"), extra.clone()));
        }
        if comment_length > 0 {
            notes.push((
                format!("the comment of member {k}"),
                bytes[comment_at..next].to_vec(),
            ));
        }
        entries.push(Entry {
            needed: u16_at(bytes, at + 6),
            flags,
            method,
            crc: u32_at(bytes, at + 16),
            packed,
            size,
            name,
            kind,
            local: local as usize,
            extra,
        });
        at = next;
    }
    if at != end {
        return Err(mismatch());
    }

    // Each local header agrees with its entry; together with their data they cover every byte
    // before the central directory exactly once.
    let mut covered = Vec::with_capacity(entries.len());
    let mut ranges = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        let k = i + 1;
        let at = entry.local;
        let header = bytes
            .get(at..at.saturating_add(LOCAL))
            .filter(|_| at + LOCAL <= central_at);
        let agrees = header.is_some_and(|header| {
            u32_at(header, 0) == LOCAL_SIGNATURE
                && u16_at(header, 4) == entry.needed
                && u16_at(header, 6) == entry.flags
                && u16_at(header, 8) == entry.method
                && u32_at(header, 14) == entry.crc
                && u32_at(header, 18) == entry.packed
                && u32_at(header, 22) == entry.size
                && usize::from(u16_at(header, 26)) == entry.name.len()
                && bytes.get(at + LOCAL..at + LOCAL + entry.name.len()) == Some(&entry.name[..])
        });
        if !agrees {
            return Err(unreadable(format_args!(
                "the local header of member {k} does not match its central directory entry"
            )));
        }
        // A local header carries no extra field, or the one of its central directory entry.
        let extra_at = at + LOCAL + entry.name.len();
        let extra_length = usize::from(u16_at(bytes, at + 28));
        if extra_length != 0
            && bytes.get(extra_at..extra_at + extra_length) != Some(&entry.extra[..])
        {
            return Err(unreadable(format_args!(
                "the local header of member {k} does not match its central directory entry"
            )));
        }
        let start = extra_at + extra_length;
        let stop = start + entry.packed as usize;
        if stop > central_at {
            return Err(unreadable(format_args!("member {k} is cut short")));
        }
        covered.push((at, stop));
        ranges.push(start..stop);
    }
    covered.sort_unstable();
    let mut next = 0;
    for (start, stop) in covered {
        if start != next {
            return Err(unreadable(
                "the members overlap or leave bytes no zip structure describes",
            ));
        }
        next = stop;
    }
    if next != central_at {
        return Err(unreadable(
            "the members overlap or leave bytes no zip structure describes",
        ));
    }

    let over = || {
        unreadable(format_args!(
            "it unpacks to more than {} MiB, the most the scan reads",
            max_bytes / (1024 * 1024)
        ))
    };
    let mut data = Vec::new();
    let mut members = Vec::with_capacity(entries.len());
    for (i, (entry, range)) in entries.into_iter().zip(ranges).enumerate() {
        let k = i + 1;
        let declared = u64::from(entry.size);
        if data.len() as u64 + declared > max_bytes {
            return Err(over());
        }
        let packed = &bytes[range];
        let size = || {
            unreadable(format_args!(
                "member {k} unpacks to a size other than its declared size"
            ))
        };
        let start = data.len();
        if entry.method == STORED {
            if packed.len() as u64 != declared {
                return Err(size());
            }
            data.extend_from_slice(packed);
        } else {
            let mut decoder = flate2::bufread::DeflateDecoder::new(packed);
            // Bounded while reading: a stream that unpacks to more than declared stops there.
            (&mut decoder)
                .take(declared + 1)
                .read_to_end(&mut data)
                .map_err(|_| {
                    unreadable(format_args!(
                        "the deflate stream of member {k} is corrupt or cut short"
                    ))
                })?;
            if (data.len() - start) as u64 != declared {
                return Err(size());
            }
            if !decoder.into_inner().is_empty() {
                return Err(unreadable(format_args!(
                    "data follows the deflate stream of member {k}"
                )));
            }
        }
        let mut crc = flate2::Crc::new();
        crc.update(&data[start..]);
        if crc.sum() != entry.crc {
            return Err(unreadable(format_args!(
                "the CRC-32 of member {k} does not match its data"
            )));
        }
        members.push(Member {
            name: entry.name,
            kind: entry.kind,
            data: start..data.len(),
        });
    }
    Ok(Archive {
        notes,
        data,
        members,
    })
}

/// The offset of the end record: the one place where its signature starts and its comment
/// ends the file.
fn end_record(bytes: &[u8]) -> Result<usize> {
    let missing = || unreadable("the end of central directory record is missing or ambiguous");
    let last = bytes.len().checked_sub(END).ok_or_else(missing)?;
    let first = last.saturating_sub(usize::from(u16::MAX));
    let mut ends = (first..=last).filter(|&at| {
        u32_at(bytes, at) == END_SIGNATURE
            && at + END + usize::from(u16_at(bytes, at + 20)) == bytes.len()
    });
    match (ends.next(), ends.next()) {
        (Some(at), None) => Ok(at),
        _ => Err(missing()),
    }
}
