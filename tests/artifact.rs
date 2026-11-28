#[path = "support/formats.rs"]
mod formats;

use b10x_gates::{digest, policy::Policy};
use formats::{
    CPU_X86_64, MACHO_SECTION, MACHO_SECTIONS, MH_DYLIB, MH_EXECUTE, MH_OBJECT, PE_COFF, PE_DLL,
    PE_EXECUTABLE, coff_object, macho_fat, macho64, macho64_with, pe, pe_sections, pe_with,
};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn section(
    bytes: &mut [u8],
    offset: usize,
    name: u32,
    kind: u32,
    flags: u64,
    file_offset: usize,
    size: usize,
) {
    put_u32(bytes, offset, name);
    put_u32(bytes, offset + 4, kind);
    put_u64(bytes, offset + 8, flags);
    put_u64(bytes, offset + 24, file_offset as u64);
    put_u64(bytes, offset + 32, size as u64);
    put_u64(bytes, offset + 48, 1);
}

/// A minimal ELF64 little-endian executable with one executable and one data section.
fn elf64(text: &[u8], data: &[u8]) -> Vec<u8> {
    const HEADER: usize = 64;
    const SECTION_HEADER: usize = 64;
    const SHSTRTAB: &[u8] = b"\0.text\0.data\0.bss\0.shstrtab\0";
    let text_offset = HEADER;
    let data_offset = text_offset + text.len();
    let names_offset = data_offset + data.len();
    let sections_offset = (names_offset + SHSTRTAB.len() + 7) & !7;
    let mut bytes = vec![0u8; sections_offset + 5 * SECTION_HEADER];
    bytes[..16].copy_from_slice(&[0x7f, b'E', b'L', b'F', 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    put_u16(&mut bytes, 16, 2); // ET_EXEC
    put_u16(&mut bytes, 18, 62); // EM_X86_64
    put_u32(&mut bytes, 20, 1);
    put_u64(&mut bytes, 40, sections_offset as u64);
    put_u16(&mut bytes, 52, HEADER as u16);
    put_u16(&mut bytes, 58, SECTION_HEADER as u16);
    put_u16(&mut bytes, 60, 5);
    put_u16(&mut bytes, 62, 4);
    bytes[text_offset..data_offset].copy_from_slice(text);
    bytes[data_offset..names_offset].copy_from_slice(data);
    bytes[names_offset..names_offset + SHSTRTAB.len()].copy_from_slice(SHSTRTAB);
    section(
        &mut bytes,
        sections_offset + SECTION_HEADER,
        1,
        1,
        0x6,
        text_offset,
        text.len(),
    );
    section(
        &mut bytes,
        sections_offset + 2 * SECTION_HEADER,
        7,
        1,
        0x3,
        data_offset,
        data.len(),
    );
    section(
        &mut bytes,
        sections_offset + 3 * SECTION_HEADER,
        13,
        8,
        0x3,
        names_offset,
        128,
    );
    section(
        &mut bytes,
        sections_offset + 4 * SECTION_HEADER,
        18,
        3,
        0,
        names_offset,
        SHSTRTAB.len(),
    );
    bytes
}

fn with_program_header(mut bytes: Vec<u8>, kind: u32, offset: u64, size: u64) -> Vec<u8> {
    const HEADER: usize = 64;
    const PROGRAM_HEADER: usize = 56;
    const SECTION_HEADER: usize = 64;
    let old_sections = u64::from_le_bytes(bytes[40..48].try_into().unwrap()) as usize;
    let section_count = u16::from_le_bytes(bytes[60..62].try_into().unwrap()) as usize;
    bytes.splice(HEADER..HEADER, [0u8; PROGRAM_HEADER]);
    let sections = old_sections + PROGRAM_HEADER;
    put_u64(&mut bytes, 32, HEADER as u64);
    put_u64(&mut bytes, 40, sections as u64);
    put_u16(&mut bytes, 54, PROGRAM_HEADER as u16);
    put_u16(&mut bytes, 56, 1);
    put_u32(&mut bytes, HEADER, kind);
    put_u64(&mut bytes, HEADER + 8, offset);
    put_u64(&mut bytes, HEADER + 32, size);
    for index in 1..section_count {
        let entry = sections + index * SECTION_HEADER;
        let section_kind = u32::from_le_bytes(bytes[entry + 4..entry + 8].try_into().unwrap());
        if section_kind != object::elf::SHT_NOBITS.0 {
            let old_offset = u64::from_le_bytes(bytes[entry + 24..entry + 32].try_into().unwrap());
            put_u64(&mut bytes, entry + 24, old_offset + PROGRAM_HEADER as u64);
        }
    }
    bytes
}

struct Fixture {
    root: tempfile::TempDir,
    policy: PathBuf,
    scanner: PathBuf,
}

impl Fixture {
    fn new(forbidden: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let policy = root.path().join("policy.json");
        let value = Policy {
            version: 1,
            nonce: "synthetic-artifact-policy-nonce-1234567890".into(),
            forbidden_literals: vec![forbidden.into()],
            forbidden_patterns: vec![],
            allow_patterns: vec![],
            repositories: BTreeMap::new(),
            signers: BTreeMap::new(),
            exceptions: vec![],
        };
        fs::write(&policy, serde_json::to_vec(&value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&policy, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let scanner = std::env::var_os("B10X_GATES_GITLEAKS")
            .map(PathBuf::from)
            .expect("set B10X_GATES_GITLEAKS to the pinned scanner; this test must not skip");
        Self {
            root,
            policy,
            scanner,
        }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let path = self.root.path().join(name);
        fs::write(&path, bytes).unwrap();
        path
    }

    fn run_with_scanner(&self, artifact: &Path, scanner: &Path) -> Output {
        Command::new(env!("CARGO_BIN_EXE_b10x-gates"))
            .args(["--policy", self.policy.to_str().unwrap()])
            .args(["--gitleaks", scanner.to_str().unwrap()])
            .arg("scan-artifact")
            .arg(artifact)
            .output()
            .unwrap()
    }

    fn run(&self, artifact: &Path) -> Output {
        self.run_with_scanner(artifact, &self.scanner)
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn instruction_bytes_are_not_prose_but_the_complete_artifact_digest_is_reported() {
    let fixture = Fixture::new("xyz");
    let bytes = elf64(b"\x90xyz\x90", b"safe release metadata\n");
    let artifact = fixture.write("artifact", &bytes);
    let output = fixture.run(&artifact);
    assert!(output.status.success(), "{}", stderr(&output));
    let report = stdout(&output);
    assert!(report.contains("format=elf64-little-endian"), "{report}");
    assert!(
        report.contains(&format!("sha256={}", digest(&bytes))),
        "{report}"
    );
    assert!(report.contains("scanner_invocations=1"), "{report}");
    assert!(!report.contains("extracted_bytes=0"), "{report}");
}

#[test]
fn private_identifiers_and_personal_paths_in_data_are_refused_without_echoing_them() {
    for forbidden in ["xyz", &["private", "fixture", "identifier"].join("-")] {
        let fixture = Fixture::new(forbidden);
        let artifact = fixture.write("artifact", &elf64(b"\x90\x90", forbidden.as_bytes()));
        let output = fixture.run(&artifact);
        assert!(!output.status.success(), "{forbidden}");
        assert!(
            stderr(&output).contains("private rule"),
            "{}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains(forbidden));
    }

    let fixture = Fixture::new("xyz");
    let personal = ["", "home", "fixture-person", "release"].join("/");
    let artifact = fixture.write("artifact", &elf64(b"\x90\x90", personal.as_bytes()));
    let output = fixture.run(&artifact);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("personal-paths"),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(&personal));
}

#[test]
fn unicode_format_characters_in_non_executable_data_cannot_split_a_private_identifier() {
    let fixture = Fixture::new("xyz");
    let disguised = "x\u{200b}yz";
    let artifact = fixture.write("artifact", &elf64(b"\x90\x90", disguised.as_bytes()));
    let output = fixture.run(&artifact);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("private rule"),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(disguised));
}

#[test]
fn executable_section_flags_do_not_hide_a_printable_identifier() {
    let forbidden = ["long", "private", "fixture", "identifier"].join("-");
    let fixture = Fixture::new(&forbidden);
    let mut text = vec![0x90];
    text.extend_from_slice(forbidden.as_bytes());
    text.push(0x90);
    let artifact = fixture.write("artifact", &elf64(&text, b"safe\n"));
    let output = fixture.run(&artifact);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("private rule"),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(&forbidden));
}

#[test]
fn the_real_pinned_scanner_refuses_a_synthetic_secret_even_in_an_executable_section() {
    let fixture = Fixture::new("xyz");
    let token = format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let data = format!("release_token={token}\n");
    for (name, bytes) in [
        ("secret-data", elf64(b"\x90\x90", data.as_bytes())),
        ("secret-executable", elf64(data.as_bytes(), b"safe\n")),
    ] {
        let artifact = fixture.write(name, &bytes);
        let output = fixture.run(&artifact);
        assert!(!output.status.success());
        assert!(stderr(&output).contains("secret"), "{}", stderr(&output));
        assert!(!stderr(&output).contains(&token));
    }
}

#[test]
fn missing_or_failing_secret_scanning_is_a_refusal() {
    let fixture = Fixture::new("xyz");
    let artifact = fixture.write("artifact", &elf64(b"\x90\x90", b"safe metadata\n"));
    let missing = fixture.root.path().join("missing-scanner");
    let output = fixture.run_with_scanner(&artifact, &missing);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("pinned Gitleaks binary unavailable"),
        "{}",
        stderr(&output)
    );
    assert!(!stdout(&output).contains("scanner_invocations=0"));
}

#[test]
fn unsupported_and_incomplete_artifacts_are_refused_before_scanning() {
    let fixture = Fixture::new("xyz");
    let valid = elf64(b"\x90\x90", b"safe metadata\n");
    let mut elf32 = valid.clone();
    elf32[4] = 1;
    let mut big_endian = valid.clone();
    big_endian[5] = 2;
    let mut relocatable = valid.clone();
    put_u16(&mut relocatable, 16, 1);
    let mut no_sections = valid.clone();
    put_u64(&mut no_sections, 40, 0);
    put_u16(&mut no_sections, 60, 0);

    for (name, bytes) in [
        ("plain", b"not an executable".to_vec()),
        ("elf32", elf32),
        ("big-endian", big_endian),
        ("relocatable", relocatable),
        ("no-sections", no_sections),
    ] {
        let artifact = fixture.write(name, &bytes);
        let output = fixture.run_with_scanner(&artifact, Path::new("missing-scanner"));
        assert!(!output.status.success(), "{name}");
        assert!(
            stderr(&output).contains("artifact format unsupported")
                || stderr(&output).contains("section inventory invalid"),
            "{name}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn truncated_and_out_of_bounds_sections_are_refused_before_scanning() {
    let fixture = Fixture::new("xyz");
    let valid = elf64(b"\x90\x90", b"safe metadata\n");
    let truncated = valid[..valid.len() - 12].to_vec();
    let mut bad_range = valid.clone();
    let sections = u64::from_le_bytes(bad_range[40..48].try_into().unwrap()) as usize;
    put_u64(&mut bad_range, sections + 2 * 64 + 24, u64::MAX - 7);

    for (name, bytes) in [("truncated", truncated), ("bad-range", bad_range)] {
        let artifact = fixture.write(name, &bytes);
        let output = fixture.run_with_scanner(&artifact, Path::new("missing-scanner"));
        assert!(!output.status.success(), "{name}");
        assert!(
            stderr(&output).contains("artifact format invalid")
                || stderr(&output).contains("section range invalid"),
            "{name}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn every_program_header_file_range_is_validated_before_scanning() {
    let fixture = Fixture::new("xyz");
    for kind in [
        object::elf::PT_LOAD,
        object::elf::PT_DYNAMIC,
        object::elf::PT_INTERP,
        object::elf::PT_NOTE,
        object::elf::PT_TLS,
    ] {
        let bytes = with_program_header(
            elf64(b"\x90\x90", b"safe metadata\n"),
            kind.0,
            u64::MAX - 7,
            16,
        );
        let artifact = fixture.write(&format!("bad-program-header-{kind:?}"), &bytes);
        let output = fixture.run_with_scanner(&artifact, Path::new("missing-scanner"));
        assert!(
            !output.status.success(),
            "program type {kind:?} was accepted"
        );
        assert!(
            stderr(&output).contains("artifact segment range invalid"),
            "program type {kind:?}: {}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains("pinned Gitleaks binary unavailable"));
    }
}

/// `gates.delivery.ValidateArtifact`, outcome `static-name-service`: a statically linked
/// glibc loads the host's `libnss_*` modules to resolve a name and crashed 0.1.19 on its
/// second GitHub request. Such an executable is refused before any scanner runs.
#[test]
fn a_static_executable_carrying_glibc_name_service_switch_is_refused_before_scanning() {
    let fixture = Fixture::new("xyz");
    let bytes = elf64(b"\x90\x90", b"/etc/nsswitch.conf\0libnss_\0");
    let artifact = fixture.write("static-glibc", &bytes);
    let output = fixture.run_with_scanner(&artifact, Path::new("missing-scanner"));
    assert!(!output.status.success(), "{}", stdout(&output));
    let refusal = stderr(&output);
    assert!(
        refusal.contains("statically linked") && refusal.contains("x86_64-unknown-linux-musl"),
        "{refusal}"
    );
}

#[test]
fn a_dynamic_executable_or_a_static_one_without_name_service_switch_is_not_refused_by_it() {
    let fixture = Fixture::new("xyz");
    let dynamic = with_program_header(
        elf64(b"\x90\x90", b"/etc/nsswitch.conf\0safe metadata\n"),
        object::elf::PT_INTERP.0,
        0,
        16,
    );
    let musl = elf64(b"\x90\x90", b"safe release metadata\n");
    for (name, bytes) in [("dynamic-glibc", dynamic), ("static-musl", musl)] {
        let artifact = fixture.write(name, &bytes);
        let output = fixture.run(&artifact);
        assert!(output.status.success(), "{name}: {}", stderr(&output));
    }
}

// Mach-O and PE executables are validated the way an ELF executable is: a complete, bounded,
// in-range and non-overlapping section inventory; every byte of non-executable sections and
// printable runs of four bytes or more of the whole file to the private rules; printable runs
// to the pinned secret scanner. No rule is exempted for them.

/// A Mach-O universal file of an arm64 slice and an x86-64 slice built from `text` and `data`.
fn fat(text: &[u8], data: &[u8]) -> Vec<u8> {
    macho_fat(
        &[
            macho64(b"\x90\x90", b"safe release metadata\n"),
            macho64_with(MH_EXECUTE, CPU_X86_64, text, data, None),
        ],
        b"",
    )
}

fn pe64(text: &[u8], data: &[u8]) -> Vec<u8> {
    pe(true, text, data)
}

fn pe32(text: &[u8], data: &[u8]) -> Vec<u8> {
    pe(false, text, data)
}

type Build = fn(&[u8], &[u8]) -> Vec<u8>;

/// Each format beside ELF, with the format `scan-artifact` reports for it.
const FORMATS: [(&str, Build, &str); 4] = [
    ("macho-thin", macho64, "format=macho64-little-endian"),
    ("macho-fat", fat, "format=macho-universal"),
    ("pe32plus", pe64, "format=pe32+"),
    ("pe32", pe32, "format=pe32;"),
];

#[test]
fn clean_macho_and_pe_executables_pass_with_the_complete_artifact_digest() {
    let fixture = Fixture::new("xyz");
    let mut cases: Vec<(String, Vec<u8>, &str)> = FORMATS
        .iter()
        .map(|(name, build, format)| {
            (
                name.to_string(),
                build(b"\x90xyz\x90", b"safe release metadata\n"),
                *format,
            )
        })
        .collect();
    cases.push((
        "macho-dylib".into(),
        macho64_with(MH_DYLIB, CPU_X86_64, b"\x90\x90", b"safe metadata\n", None),
        "format=macho64-little-endian",
    ));
    cases.push((
        "macho-not-yet-encrypted".into(),
        macho64_with(
            MH_EXECUTE,
            CPU_X86_64,
            b"\x90\x90",
            b"safe metadata\n",
            Some(0),
        ),
        "format=macho64-little-endian",
    ));
    cases.push((
        "pe-dll".into(),
        pe_with(
            true,
            PE_EXECUTABLE | PE_DLL,
            b"\x90\x90",
            b"safe metadata\n",
        ),
        "format=pe32+",
    ));
    for (name, bytes, format) in cases {
        let artifact = fixture.write(&name, &bytes);
        let output = fixture.run(&artifact);
        assert!(output.status.success(), "{name}: {}", stderr(&output));
        let report = stdout(&output);
        assert!(report.contains(format), "{name}: {report}");
        assert!(
            report.contains(&format!("sha256={}", digest(&bytes))),
            "{name}: {report}"
        );
        assert!(report.contains("scanner_invocations=1"), "{name}: {report}");
        assert!(!report.contains("extracted_bytes=0"), "{name}: {report}");
    }
}

#[test]
fn private_identifiers_and_personal_paths_in_macho_and_pe_data_are_refused() {
    let forbidden = ["private", "fixture", "identifier"].join("-");
    let fixture = Fixture::new(&forbidden);
    let short = Fixture::new("xyz");
    // A runner's home directory is a personal path like any other: no exemption.
    let paths = [
        ["", "Users", "runner", "work", "tool", "src", "main.rs"].join("/"),
        ["", "home", "runner", "work", "tool", "src", "main.rs"].join("/"),
    ];
    for (format, build, _) in FORMATS {
        // Three bytes in a data section: only the raw section bytes carry them.
        for (data, rule, hidden) in [
            (b"\0xyz\0".to_vec(), "private rule", "xyz"),
            (
                forbidden.as_bytes().to_vec(),
                "private rule",
                &forbidden[..],
            ),
            (
                paths[0].as_bytes().to_vec(),
                "personal-paths",
                &paths[0][..],
            ),
            (
                paths[1].as_bytes().to_vec(),
                "personal-paths",
                &paths[1][..],
            ),
        ] {
            let fixture = if hidden == "xyz" { &short } else { &fixture };
            let artifact = fixture.write(format, &build(b"\x90\x90", &data));
            let output = fixture.run_with_scanner(&artifact, Path::new("missing-scanner"));
            assert!(!output.status.success(), "{format}: {hidden}");
            assert!(
                stderr(&output).contains(rule),
                "{format}: {}",
                stderr(&output)
            );
            assert!(!stderr(&output).contains(hidden), "{format}");
        }
    }
}

#[test]
fn executable_section_flags_do_not_hide_a_printable_identifier_in_macho_or_pe() {
    let forbidden = ["long", "private", "fixture", "identifier"].join("-");
    let fixture = Fixture::new(&forbidden);
    let mut text = vec![0x90];
    text.extend_from_slice(forbidden.as_bytes());
    text.push(0x90);
    for (format, build, _) in FORMATS {
        let artifact = fixture.write(format, &build(&text, b"safe\n"));
        let output = fixture.run_with_scanner(&artifact, Path::new("missing-scanner"));
        assert!(!output.status.success(), "{format}");
        assert!(
            stderr(&output).contains("private rule"),
            "{format}: {}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains(&forbidden));
    }
}

#[test]
fn bytes_of_a_universal_file_outside_every_slice_are_scanned() {
    let forbidden = ["long", "private", "fixture", "identifier"].join("-");
    let fixture = Fixture::new(&forbidden);
    let mut gap = vec![0];
    gap.extend_from_slice(forbidden.as_bytes());
    gap.push(0);
    let bytes = macho_fat(
        &[
            macho64(b"\x90\x90", b"safe release metadata\n"),
            macho64_with(MH_EXECUTE, CPU_X86_64, b"\x90\x90", b"safe\n", None),
        ],
        &gap,
    );
    let artifact = fixture.write("fat-gap", &bytes);
    let output = fixture.run_with_scanner(&artifact, Path::new("missing-scanner"));
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("private rule"),
        "{}",
        stderr(&output)
    );
    assert!(!stderr(&output).contains(&forbidden));
}

/// Each format costs two runs of the pinned scanner, so the formats are split over two tests
/// that run in parallel.
fn secret_refused(formats: &[(&str, Build, &str)]) {
    let fixture = Fixture::new("xyz");
    let token = format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
    let data = format!("release_token={token}\n");
    for (format, build, _) in formats {
        for (name, bytes) in [
            ("data", build(b"\x90\x90", data.as_bytes())),
            ("executable", build(data.as_bytes(), b"safe\n")),
        ] {
            let artifact = fixture.write(&format!("{format}-{name}"), &bytes);
            let output = fixture.run(&artifact);
            assert!(!output.status.success(), "{format}-{name}");
            assert!(
                stderr(&output).contains("secret"),
                "{format}-{name}: {}",
                stderr(&output)
            );
            assert!(!stderr(&output).contains(&token));
        }
    }
}

#[test]
fn the_real_pinned_scanner_refuses_a_synthetic_secret_in_macho() {
    secret_refused(&FORMATS[..2]);
}

#[test]
fn the_real_pinned_scanner_refuses_a_synthetic_secret_in_pe() {
    secret_refused(&FORMATS[2..]);
}

fn put_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

#[test]
fn unsupported_macho_and_pe_kinds_and_unknown_formats_are_refused_before_scanning() {
    let fixture = Fixture::new("xyz");
    let thin = macho64(b"\x90\x90", b"safe metadata\n");
    let mut macho32 = thin.clone();
    put_u32(&mut macho32, 0, 0xfeed_face);
    let mut big_endian = thin.clone();
    put_u32_be(&mut big_endian, 0, 0xfeed_facf);
    let object = macho64_with(MH_OBJECT, CPU_X86_64, b"\x90\x90", b"safe\n", None);
    let fat_of_object = macho_fat(&[thin.clone(), object.clone()], b"");
    let fat_of_fat = macho_fat(&[macho_fat(std::slice::from_ref(&thin), b"")], b"");
    let empty_fat = macho_fat(&[], b"");
    let not_an_image = pe_with(true, 0x0020, b"\x90\x90", b"safe metadata\n");
    let system = pe_with(
        true,
        PE_EXECUTABLE | 0x1000,
        b"\x90\x90",
        b"safe metadata\n",
    );
    let mut dos = vec![0u8; 128];
    dos[..2].copy_from_slice(b"MZ");
    let mut java = vec![0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x34];
    java.extend_from_slice(&[0u8; 64]);
    let wasm = b"\0asm\x01\0\0\0\0\0\0\0\0\0\0\0".to_vec();

    for (name, bytes) in [
        ("macho32", macho32),
        ("macho-big-endian", big_endian),
        ("macho-object", object),
        ("fat-of-object", fat_of_object),
        ("fat-of-fat", fat_of_fat),
        ("empty-fat", empty_fat),
        ("pe-not-an-image", not_an_image),
        ("pe-system", system),
        ("coff-object", coff_object()),
        ("dos", dos),
        ("java-class", java),
        ("wasm", wasm),
    ] {
        let artifact = fixture.write(name, &bytes);
        let output = fixture.run_with_scanner(&artifact, Path::new("missing-scanner"));
        assert!(!output.status.success(), "{name}");
        assert!(
            stderr(&output).contains("artifact format unsupported")
                || stderr(&output).contains("artifact format invalid")
                || stderr(&output).contains("section inventory invalid"),
            "{name}: {}",
            stderr(&output)
        );
        assert!(!stderr(&output).contains("pinned Gitleaks binary unavailable"));
    }
}

#[test]
fn malformed_macho_and_pe_section_inventories_are_refused_before_scanning() {
    let fixture = Fixture::new("xyz");
    let thin = macho64(b"\x90\x90", b"safe metadata\n");
    let text = MACHO_SECTIONS;
    let data = MACHO_SECTIONS + MACHO_SECTION;
    let text_at = u32::from_le_bytes(thin[text + 48..text + 52].try_into().unwrap());
    let mut macho_out_of_range = thin.clone();
    put_u32(&mut macho_out_of_range, data + 48, u32::MAX - 7);
    let mut macho_overlap = thin.clone();
    put_u32(&mut macho_overlap, data + 48, text_at);
    let mut macho_segment = thin.clone();
    put_u64(&mut macho_segment, 32 + 48, u64::MAX - 7);
    let mut macho_compressed = thin.clone();
    macho_compressed[data..data + 16].copy_from_slice(b"__zdebug_info\0\0\0");
    let encrypted = macho64_with(MH_EXECUTE, CPU_X86_64, b"\x90\x90", b"safe\n", Some(1));
    let mut fat_out_of_range = macho_fat(std::slice::from_ref(&thin), b"");
    put_u32_be(&mut fat_out_of_range, 8 + 12, u32::MAX - 7);
    let mut fat_overlap = macho_fat(&[thin.clone(), thin.clone()], b"");
    let first = u32::from_be_bytes(fat_overlap[8 + 8..8 + 12].try_into().unwrap());
    put_u32_be(&mut fat_overlap, 8 + 20 + 8, first);

    let image = pe(true, b"\x90\x90", b"safe metadata\n");
    let table = pe_sections(true);
    let text_raw = u32::from_le_bytes(image[table + 20..table + 24].try_into().unwrap());
    let mut pe_out_of_range = image.clone();
    put_u32(&mut pe_out_of_range, table + 40 + 20, u32::MAX - 7);
    // The raw size runs past the end of the file while the virtual size stays inside it.
    let mut pe_raw_past_end = image.clone();
    put_u32(&mut pe_raw_past_end, table + 40 + 16, 0x10_0000);
    let mut pe_overlap = image.clone();
    put_u32(&mut pe_overlap, table + 40 + 20, text_raw);
    let mut pe_compressed = image.clone();
    pe_compressed[table + 40..table + 48].copy_from_slice(b".zdebug_");
    let mut pe_no_sections = image.clone();
    put_u16(&mut pe_no_sections, PE_COFF + 2, 0);
    let truncated = image[..image.len() - 0x300].to_vec();

    for (name, bytes) in [
        ("macho-out-of-range", macho_out_of_range),
        ("macho-overlap", macho_overlap),
        ("macho-segment", macho_segment),
        ("macho-compressed", macho_compressed),
        ("macho-encrypted", encrypted),
        ("fat-out-of-range", fat_out_of_range),
        ("fat-overlap", fat_overlap),
        ("pe-out-of-range", pe_out_of_range),
        ("pe-raw-past-end", pe_raw_past_end),
        ("pe-overlap", pe_overlap),
        ("pe-compressed", pe_compressed),
        ("pe-no-sections", pe_no_sections),
        ("pe-truncated", truncated),
    ] {
        let artifact = fixture.write(name, &bytes);
        let output = fixture.run_with_scanner(&artifact, Path::new("missing-scanner"));
        assert!(!output.status.success(), "{name}");
        let refusal = stderr(&output);
        assert!(
            [
                "artifact format invalid",
                "section range invalid",
                "section ranges overlap",
                "segment range invalid",
                "slice range invalid",
                "slice ranges overlap",
                "section inventory invalid",
                "compressed artifact sections are unsupported",
                "encrypted artifact sections are unsupported",
            ]
            .iter()
            .any(|reason| refusal.contains(reason)),
            "{name}: {refusal}"
        );
        assert!(!refusal.contains("pinned Gitleaks binary unavailable"));
    }
}
