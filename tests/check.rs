//! `gsr::check` on small scripts, one rule at a time.

use gsr::{check, Decoding, Report, Rule, Severity};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn rules(r: &Report) -> Vec<(&'static str, usize, Option<usize>)> {
    r.diagnostics.iter().map(|d| (d.rule.id(), d.offset, d.declaration)).collect()
}

fn errors(r: &Report) -> Vec<(&'static str, usize, Option<usize>)> {
    r.diagnostics
        .iter()
        .filter(|d| d.severity() == Severity::Error)
        .map(|d| (d.rule.id(), d.offset, d.declaration))
        .collect()
}

#[test]
fn clean_scripts() {
    // OP_ADD OP_3 OP_EQUAL: two witness items
    let r = check(&hex("93 53 87"));
    assert_eq!((r.decoding, rules(&r), r.witness_items), (Decoding::WellFormed, vec![], Some(vec![2])));
    // OP_IF OP_DROP OP_ELSE OP_2DROP OP_ENDIF OP_1: the branches take 2 or 3 items
    let r = check(&hex("63 75 67 6d 68 51"));
    assert_eq!((rules(&r), r.witness_items), (vec![], Some(vec![2, 3])));
    // a macro used twice
    let r = check(&hex("d0 01 93  d1 00 d1 00"));
    assert_eq!((rules(&r), r.witness_items), (vec![], Some(vec![3])));
}

#[test]
fn op_success() {
    // OP_1NEGATE, ordinary in Tapscript, is an OP_SUCCESSx in Tapleaf 0xC2
    let r = check(&hex("4f 51"));
    assert_eq!((r.decoding, rules(&r)), (Decoding::OpSuccess, vec![("op-success", 0, None)]));
    // in a body nothing references, and before a malformed declaration header
    let r = check(&hex("d0 01 8f  d0 05"));
    assert_eq!(r.decoding, Decoding::OpSuccess);
    assert_eq!(rules(&r), vec![("op-success", 2, Some(0)), ("malformed", 3, None)]);
}

#[test]
fn malformed() {
    // a truncated push in a body precedes the OP_SUCCESSx after it
    let r = check(&hex("d0 01 4c  50"));
    assert_eq!((r.decoding, rules(&r)), (Decoding::Malformed, vec![("malformed", 2, Some(0))]));
    // a reference to a later declaration
    let r = check(&hex("d0 02 d1 01  d0 01 51  51"));
    assert_eq!((r.decoding, rules(&r)), (Decoding::Malformed, vec![("malformed", 2, Some(0))]));
}

#[test]
fn unrolled_size() {
    // 24 doublings of OP_NOP: 2^24 bytes
    let mut s = hex("d0 01 61");
    for k in 0..24u8 {
        s.extend([0xd0, 4, 0xd1, k, 0xd1, k]);
    }
    s.extend([0xd1, 24, 0x51]);
    let r = check(&s);
    assert_eq!(rules(&r)[0].0, "unrolled-size");
}

#[test]
fn always_fails() {
    // OP_RETURN outside any branch
    assert_eq!(rules(&check(&hex("51 6a"))), vec![("always-fails", 1, None)]);
    // in one branch only: fine
    assert_eq!(rules(&check(&hex("63 6a 67 68 51"))), vec![]);
    // in both branches
    assert_eq!(rules(&check(&hex("63 6a 67 6a 68 51"))), vec![("always-fails", 3, None)]);
    // OP_VERIF fails even in a branch that is not taken
    assert_eq!(rules(&check(&hex("00 63 65 68 51"))), vec![("always-fails", 2, None)]);
    // OP_CHECKMULTISIG in a macro body
    assert_eq!(errors(&check(&hex("d0 01 ae  51 d1 00"))), vec![("always-fails", 2, Some(0))]);
}

#[test]
fn unbalanced_conditional() {
    assert_eq!(rules(&check(&hex("51 68 51"))), vec![("unbalanced-conditional", 1, None)]);
    let r = check(&hex("51 63 51"));
    assert_eq!(rules(&r), vec![("unbalanced-conditional", 1, None)]);
    assert!(r.stack_analysis_stopped.is_some());
    // one macro opens the branch, another closes it
    let r = check(&hex("d0 01 63  d0 01 68  d1 00 51 d1 01"));
    assert_eq!((errors(&r), r.witness_items), (vec![], Some(vec![1, 2])));
}

#[test]
fn stacks() {
    assert_eq!(rules(&check(&hex("6c 51"))), vec![("altstack-underflow", 0, None)]);
    assert_eq!(rules(&check(&hex("51 6b 6c"))), vec![]);
    // OP_1 OP_1 leaves two items even with an empty witness
    assert_eq!(rules(&check(&hex("51 51"))), vec![("stack-unsatisfiable", 2, None)]);
    // OP_2 OP_PICK needs 3 witness items but then leaves 4
    assert_eq!(rules(&check(&hex("52 79"))), vec![("stack-unsatisfiable", 1, None)]);
    // OP_IFDUP OP_DROP: a nonzero item alone, or a zero on top of another
    assert_eq!(check(&hex("73 75")).witness_items, Some(vec![1, 2]));
    // OP_DEPTH OP_PICK: the depth is not known
    let r = check(&hex("74 79"));
    assert_eq!((r.witness_items, r.stack_analysis_stopped.map(|s| s.offset)), (None, Some(1)));
}

#[test]
fn policy() {
    let r = check(&hex("01 05 75  4c 01 81 75  01 81 75  b3 51"));
    let expected = vec![("non-minimal-push", 0, None), ("non-minimal-push", 3, None), ("upgradable-nop", 10, None)];
    assert_eq!(rules(&r), expected);
    assert!(r.diagnostics.iter().all(|d| d.severity() == Severity::Warning));
    // OP_0 and a direct push of 0x81 (OP_1NEGATE is an OP_SUCCESSx) are minimal
    assert_eq!(rules(&check(&hex("00 75 01 81"))), vec![]);
}

#[test]
fn macro_lints() {
    // macro 0 is never reached, macro 1 is referenced once
    let r = check(&hex("d0 01 93  d0 01 94  d1 01"));
    assert_eq!(rules(&r), vec![("unused-macro", 0, Some(0)), ("single-use-macro", 3, Some(1))]);
    assert!(r.diagnostics.iter().all(|d| d.severity() == Severity::Lint));
    assert_eq!(r.diagnostics[0].rule, Rule::UnusedMacro);
}
