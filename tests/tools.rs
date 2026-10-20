//! `gsr::disasm`, `gsr::attribute`, `gsr::near_duplicates` and `gsr::anchor_auto` on small scripts.

use gsr::{anchor_auto, attribute, disasm, near_duplicates, LabelledRange};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn range(start: usize, end: usize, label: &str) -> LabelledRange {
    LabelledRange { start, end, label: label.into() }
}

#[test]
fn lists_instructions() {
    // a declaration; a reference, non-minimal and minimal number pushes (0x81 included), a 32-byte push
    let script = hex(&format!("d0 03 51 52 93  d1 00  01 05  01 81  02 0001  4c 01 05  20 {}  79", "ab".repeat(32)));
    let expected = "\
; 51 bytes = declarations (1, 5 bytes) + main script (46 bytes)
macro0 @0 (3 bytes)
       2  1
       3  2
       4  ADD
main @5
       5  call0
       7  0x05
       9  129
      11  256
      14  0x05
      17  <32B>
      50  PICK
";
    assert_eq!(disasm(&script, false).unwrap(), expected);
    assert!(disasm(&script, true).unwrap().contains(&format!("      17  0x{}\n", "ab".repeat(32))));
}

#[test]
fn attributes_bytes_through_anchoring() {
    // the plain script OP_2 OP_PICK OP_NIP OP_NIP OP_NIP, anchored and compressed: OP_DEPTH OP_1 OP_SUB is a macro
    let plain = hex("52 79 77 77 77");
    let compressed = hex("d0 03 74 51 94  d1 00 79 77 77 77");
    let a = attribute(&compressed, &plain, &[range(0, 2, "read"), range(2, 5, "nips")]).unwrap();
    assert_eq!((a.bytes, a.main_bytes, a.declaration_bytes), (11, 6, 5));
    let by: Vec<(Option<&str>, f64, f64, usize, u64)> = a
        .labels
        .iter()
        .map(|l| (l.label.as_deref(), l.main_bytes, l.declaration_bytes, l.declarations, l.exclusive_declaration_bytes))
        .collect();
    assert_eq!(by, vec![(Some("read"), 3.0, 5.0, 1, 5), (Some("nips"), 3.0, 0.0, 0, 0)]);
    assert_eq!((a.labels[0].plain_bytes, a.labels[0].unrolled_bytes), (2, 4));
    // the shortest range wins; bytes no range covers are unlabelled
    let a = attribute(&compressed, &plain, &[range(0, 4, "most"), range(2, 3, "first nip")]).unwrap();
    let names: Vec<Option<&str>> = a.labels.iter().map(|l| l.label.as_deref()).collect();
    assert_eq!(names, vec![Some("most"), Some("first nip"), None]);
    assert_eq!(a.labels.iter().map(|l| l.main_bytes).collect::<Vec<_>>(), vec![4.0, 1.0, 1.0]);
    // a script that is not the plain one
    let err = attribute(&hex("52 79 77 77"), &plain, &[]).unwrap_err();
    assert!(err.contains("fewer instructions"), "{err}");
    assert!(attribute(&hex("53 79 77 77 77"), &plain, &[]).unwrap_err().contains("differ at"));
}

#[test]
fn finds_near_duplicates() {
    // `<n> OP_PICK` and six OP_ADDs, n = 20..23, between different instructions
    let x = |n: u8| format!("01 {n:02x} 79 939393939393");
    let script = hex(&format!("{} 76 {} 7c {} 7d {} 82", x(20), x(21), x(22), x(23)));
    let found = near_duplicates(&script, 2, 5).unwrap();
    assert_eq!(found.len(), 1);
    let f = &found[0];
    assert_eq!(f.pattern.join(" "), "$1 PICK ADD ADD ADD ADD ADD ADD");
    assert_eq!((f.occurrences.clone(), f.bytes, f.total_bytes), (vec![0, 10, 20, 30], 9, 36));
    let v = &f.varying[0];
    assert_eq!((v.index, v.min, v.max, v.distinct, v.step, v.before.as_deref()), (0, 20, 23, 4, Some(1), Some("PICK")));
    // one macro for 4 × 9 bytes (17) instead of one for the six OP_ADDs and PICK (11)
    assert_eq!(f.saving, 6);
    // identical occurrences are exact repeats, not near-duplicates
    let same = hex(&format!("{} 76 {} 7c {} 7d {} 82", x(20), x(20), x(20), x(20)));
    assert!(near_duplicates(&same, 2, 5).unwrap().is_empty());
}

#[test]
fn auto_threshold_keeps_the_script_without_deep_reads() {
    let script = hex("52 79 77 77 77");
    let (out, st, tried) = anchor_auto(&script, 0).unwrap();
    assert_eq!((out, st.min_depth, st.rewritten), (script, None, 0));
    assert_eq!(tried.len(), 1 + gsr::CANDIDATE_MIN_DEPTHS.len());
    assert!(tried.iter().all(|&(_, n)| n == 5));
    assert!(anchor_auto(&hex("63 75 67 6d 68 51"), 0).unwrap_err().contains("different stack depths"));
}
