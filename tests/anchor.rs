//! `gsr::anchor` on small scripts.

use gsr::{anchor, check, Anchored};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

#[test]
fn rewrites_deep_reads() {
    // three witness items: OP_2 OP_PICK reads the bottom one, at index 1 from the bottom with OP_2 pushed
    let (out, st) = anchor(&hex("52 79 77 77 77"), 2, 0).unwrap();
    assert_eq!(out, hex("74 51 94 79 77 77 77"));
    let expected =
        Anchored { input_bytes: 5, output_bytes: 7, min_depth: Some(2), rewritten: 1, kept: 0, witness_items: 3 };
    assert_eq!(st, expected);
    let (out, _) = anchor(&hex("52 7a 77 77"), 2, 0).unwrap();
    assert_eq!(out, hex("74 51 94 7a 77 77"));
    // shallower reads stay
    assert_eq!(anchor(&hex("52 79 77 77 77"), 3, 0).unwrap().0, hex("52 79 77 77 77"));
    // and non-minimal pushes
    assert_eq!(anchor(&hex("01 02 79 77 77 77"), 2, 0).unwrap().1.rewritten, 0);
    assert_eq!(anchor(&hex("4c 01 02 79 77 77 77"), 2, 0).unwrap().1.rewritten, 0);
    // so do those in the protected prefix
    let (out, st) = anchor(&hex("52 79 77 77 77"), 2, 1).unwrap();
    assert_eq!((out, st.rewritten, st.kept), (hex("52 79 77 77 77"), 0, 1));
}

#[test]
fn minimal_index_pushes() {
    // n witness items, OP_2 OP_PICK, n OP_NIPs: the index is n − 2
    for (n, push) in [(18, "60"), (19, "01 11"), (131, "01 81"), (258, "02 0001")] {
        let script = [hex("52 79"), vec![0x77; n]].concat();
        let (out, st) = anchor(&script, 2, 0).unwrap();
        assert_eq!(out, [hex(&format!("74 {push} 94 79")), vec![0x77; n]].concat(), "{n}");
        assert_eq!(st.witness_items, n as u64);
        assert_eq!(check(&out).witness_items, Some(vec![n as u64]));
    }
}

#[test]
fn heights_from_branches() {
    // both branches leave the same depth, so the read after them has one height
    let script = hex("63 51 67 52 68 53 79 77 77 77 77");
    let (out, st) = anchor(&script, 3, 0).unwrap();
    assert_eq!((st.witness_items, st.rewritten), (4, 1));
    assert_eq!(out, hex("63 51 67 52 68 74 51 94 79 77 77 77 77"));
}

#[test]
fn refuses_what_it_cannot_prove() {
    let err = |s: &str| anchor(&hex(s), 2, 0).unwrap_err();
    // two or three witness items can succeed
    assert!(err("63 75 67 6d 68 51").contains("different stack depths"));
    // OP_DEPTH OP_PICK: no witness item count ends with one item
    assert!(err("74 79").contains("1 errors"));
    assert!(err("ab 52 79 77 77 77").contains("OP_CODESEPARATOR"));
    assert!(err("74 bf").contains("stopped"));
    assert!(err("50").contains("op-success"));
}
