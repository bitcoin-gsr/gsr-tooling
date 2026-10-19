//! Byte-exact agreement with the reference outputs (the earlier Python/C++ implementation).
//!
//! `tests/data` holds small scripts. Larger ones run with `GSR_REFERENCE_DIR` set to a directory of `<name>.hex`
//! inputs, `<name>.out.hex` expected outputs and optional `<name>.protect` (a byte count). There `gsr::anchor`
//! (with the minimum depth 320) must turn each `<name>.relative.hex`, protecting `<name>.relative.protect` bytes,
//! into `<name>.anchored.hex`:
//!
//!     GSR_REFERENCE_DIR=path cargo test --release -- --ignored

use std::path::Path;

use gsr::{anchor, compress, info, lower_bounds, unroll, Bounds, Info, Report, Severity};

fn hex(path: &Path) -> Vec<u8> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    digits.chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
}

fn data(name: &str) -> Vec<u8> {
    hex(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data").join(name))
}

fn protect(dir: &Path, stem: &str) -> usize {
    std::fs::read_to_string(dir.join(format!("{stem}.protect"))).map(|s| s.trim().parse().unwrap()).unwrap_or(0)
}

fn check(input: &[u8], protect: usize, expected: &[u8]) {
    let (out, stats) = compress(input, protect).unwrap();
    assert!(out == expected, "output differs from the reference ({} vs {} bytes)", out.len(), expected.len());
    assert_eq!(unroll(&out).unwrap(), unroll(input).unwrap());
    assert_eq!((stats.input_bytes, stats.output_bytes), (input.len(), out.len()));
    assert_eq!(stats.decl_len, info(&out).unwrap().decl_len);
    // compression changes the offsets of what gsr::check finds, not the findings, and leaves no macro lints
    let findings = |r: &Report| {
        let mut rules: Vec<&str> =
            r.diagnostics.iter().filter(|d| d.severity() != Severity::Lint).map(|d| d.rule.id()).collect();
        rules.dedup();
        let stopped = r.stack_analysis_stopped.as_ref().map(|s| s.reason.clone());
        (r.decoding, r.witness_items.clone(), rules, stopped)
    };
    let (before, after) = (gsr::check(input), gsr::check(&out));
    assert_eq!(findings(&before), findings(&after));
    assert_eq!(after.count(Severity::Lint), 0);
}

#[test]
fn matches_reference_outputs() {
    check(&data("sample.hex"), 0, &data("sample.out.hex"));
    check(&data("sample.hex"), 40, &data("sample.protect40.out.hex"));
    check(&data("sample2.hex"), 0, &data("sample2.out.hex"));
}

#[test]
fn info_and_bounds() {
    let i = info(&data("sample2.out.hex")).unwrap();
    let expected = Info {
        bytes: 1706,
        declarations: 33,
        decl_len: 186,
        unrolled_bytes: 2423,
        substituted: 1223,
        references: 531,
        unrolling_charge: 543968,
    };
    assert_eq!(i, expected);
    assert_eq!(lower_bounds(&data("sample2.hex")).unwrap(), Bounds { distinct_instruction_bytes: 44, lz: 1176 });
    // without declarations there is no charge
    let plain = data("sample2.hex");
    assert_eq!(info(&plain).unwrap().unrolling_charge, 0);
}

#[test]
fn protected_prefix_stays_literal() {
    let input = data("sample.hex");
    let main = |s: &[u8]| s[info(s).unwrap().decl_len..].to_vec();
    let (out, _) = compress(&input, 40).unwrap();
    // the 32-byte push and the prologue instructions starting below 40 (sample.hex has one declaration of 6 bytes)
    let k = 33 + 3 + 1 + 2 + 1 + 3;
    assert_eq!(main(&out)[..k], main(&input)[..k]);
    let (free, _) = compress(&input, 0).unwrap();
    assert_ne!(main(&free)[..k], main(&input)[..k]);
}

#[test]
#[ignore]
fn matches_reference_scripts() {
    let dir = std::env::var("GSR_REFERENCE_DIR").expect("set GSR_REFERENCE_DIR");
    let mut n = 0;
    for entry in std::fs::read_dir(&dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        let Some(stem) = name.strip_suffix(".out.hex") else { continue };
        let input = Path::new(&dir).join(format!("{stem}.hex"));
        check(&hex(&input), protect(Path::new(&dir), stem), &hex(&path));
        eprintln!("{stem}: identical");
        n += 1;
    }
    assert!(n > 0, "no <name>.out.hex in {dir}");
}

#[test]
#[ignore]
fn matches_anchored_scripts() {
    let dir = std::env::var("GSR_REFERENCE_DIR").expect("set GSR_REFERENCE_DIR");
    let dir = Path::new(&dir);
    let mut n = 0;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap();
        let Some(stem) = name.strip_suffix(".relative.hex") else { continue };
        let (out, stats) = anchor(&hex(&path), 320, protect(dir, &format!("{stem}.relative"))).unwrap();
        let expected = hex(&dir.join(format!("{stem}.anchored.hex")));
        assert!(out == expected, "{stem}: differs from the reference ({} vs {} bytes)", out.len(), expected.len());
        assert_eq!(gsr::check(&out).witness_items, Some(vec![stats.witness_items]));
        eprintln!("{stem}: anchored identically ({} reads)", stats.rewritten);
        n += 1;
    }
    assert!(n > 0, "no <name>.relative.hex in {}", dir.display());
}
