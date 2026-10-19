//! Agreement with Bitcoin Core (jmoik/bitcoin `gsr` @ `ad6c16f`): the opcode table, and the decoding and unrolling
//! vectors of `reusable_macros.json`. `contrib/extract-core.py` extracts both into `tests/data/core`.

use gsr::opcodes::{Class, Opcode, Origin, NAMED};
use gsr::{check, info, unroll, Decoding, Rule};

fn rows(name: &str) -> Vec<Vec<String>> {
    let path = format!("{}/tests/data/core/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines().filter(|l| !l.starts_with('#')).map(|l| l.split('\t').map(String::from).collect()).collect()
}

/// A script in the vectors' notation: `OP_` names, and `0x` hex whose last byte `{n}` repeats n times.
fn script(notation: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for token in notation.split_whitespace() {
        let Some(hex) = token.strip_prefix("0x") else {
            out.push(Opcode::from_name(token).unwrap_or_else(|| panic!("unknown opcode {token}")).to_u8());
            continue;
        };
        let (hex, repeat) = match hex.split_once('{') {
            Some((hex, n)) => (hex, n.trim_end_matches('}').parse().unwrap()),
            None => (hex, 1),
        };
        let bytes: Vec<u8> =
            (0..hex.len()).step_by(2).map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap()).collect();
        let (&last, rest) = bytes.split_last().unwrap();
        out.extend_from_slice(rest);
        out.extend(std::iter::repeat(last).take(repeat));
    }
    out
}

fn origin_id(origin: Option<Origin>) -> &'static str {
    match origin {
        None => "-",
        Some(Origin::Base) => "base",
        Some(Origin::Tapscript) => "tapscript",
        Some(Origin::Bip441) => "bip441",
        Some(Origin::ExtendedPrimitives) => "extended-primitives",
        Some(Origin::OpTx) => "op-tx",
        Some(Origin::ReusableMacros) => "reusable-macros",
    }
}

#[test]
fn opcodes_match_core() {
    let table = rows("opcodes.tsv");
    assert_eq!(table.len(), 256);
    let mut effects = 0;
    for f in &table {
        let op = Opcode::from_u8(u8::from_str_radix(&f[0], 16).unwrap());
        let (name, success, handled, fails, origin) = (&f[1], f[2] == "1", f[3] == "1", f[4] == "1", &f[7]);
        if name == "-" {
            assert!(op.name().starts_with("OP_PUSHBYTES_") || op.name().starts_with("OP_SUCCESS"), "{op}");
            assert!(op.origin().is_none() || op.name().starts_with("OP_PUSHBYTES_"), "{op}");
        } else {
            assert_eq!(op.name(), name);
            assert_eq!(origin_id(op.origin()), origin, "{op}");
        }
        assert_eq!(op.is_op_success(), success, "{op}");
        // Core's interpreter fails on the opcodes it does not handle: inside OP_IF..OP_ENDIF even when not
        // executing, elsewhere when executing. Macro opcodes never reach it.
        let core = match (success, handled, fails) {
            (true, ..) => "success",
            (false, false, _) if origin == "reusable-macros" => "macro",
            (false, false, _) if (0x63..=0x68).contains(&op.to_u8()) => "fails when reached",
            (false, false, _) | (false, true, true) => "fails when executed",
            (false, true, false) => "runs",
        };
        let ours = match op.class() {
            Class::OpSuccess => "success",
            Class::Macro => "macro",
            Class::FailsWhenReached => "fails when reached",
            Class::FailsWhenExecuted => "fails when executed",
            _ => "runs",
        };
        assert_eq!(ours, core, "{op}");
        if ours == "runs" && !matches!(op.name(), "OP_IFDUP" | "OP_PICK" | "OP_ROLL" | "OP_TX") {
            assert!(op.stack_effect().is_some(), "{op}");
        }
        if f[5] != "-" {
            let e = op.stack_effect().unwrap_or_else(|| panic!("{op} has a stack effect in Core"));
            assert_eq!((e.pop.to_string(), e.push.to_string()), (f[5].clone(), f[6].clone()), "{op}");
            effects += 1;
        }
    }
    assert!(effects >= 70, "only {effects} stack effects in the fixture");
}

#[test]
fn names_round_trip() {
    for b in 0..=255u8 {
        let op = Opcode::from_u8(b);
        assert_eq!(Opcode::from_name(op.name()), Some(op));
    }
    for &(name, op) in NAMED {
        assert_eq!(Opcode::from_name(name), Some(op));
    }
    assert_eq!(Opcode::from_name("OP_TRUE"), Some(gsr::opcodes::OP_1));
    assert_eq!(Opcode::from_name("OP_SUCCESS80"), None); // OP_RESERVED has a name of its own
}

#[test]
fn decoding_vectors() {
    let mut n = 0;
    for f in rows("macro-vectors.tsv").iter().filter(|f| f[0] == "decoding") {
        let (result, declarations, s, comment) = (&f[1], &f[2], script(&f[3]), &f[4]);
        let expected = match result.as_str() {
            "well-formed" => Decoding::WellFormed,
            "success" => Decoding::OpSuccess,
            "failure" => Decoding::Malformed,
            other => panic!("{comment}: unknown result {other}"),
        };
        assert_eq!(check(&s).decoding, expected, "{comment}");
        if expected == Decoding::WellFormed {
            assert_eq!(info(&s).unwrap().declarations.to_string(), *declarations, "{comment}");
        }
        n += 1;
    }
    assert!(n >= 30);
}

#[test]
fn unrolling_vectors() {
    let mut n = 0;
    for f in rows("macro-vectors.tsv").iter().filter(|f| f[0] == "unrolling") {
        let (s, comment) = (script(&f[8]), &f[9]);
        let i = info(&s).unwrap();
        let ours = [i.declarations as u64, i.unrolled_bytes, i.substituted, i.references];
        let core: Vec<u64> = f[1..5].iter().map(|x| x.parse().unwrap()).collect();
        assert_eq!(ours[..], core[..], "{comment}");
        let within = f[5] == "1";
        if within {
            assert_eq!(i.unrolling_charge.to_string(), f[6], "{comment}");
        }
        let r = check(&s);
        assert_eq!(r.diagnostics.iter().any(|d| d.rule == Rule::UnrolledSize), !within, "{comment}");
        if f[7] != "-" {
            let expected = if f[7] == "(empty)" { Vec::new() } else { script(&f[7]) };
            assert_eq!(unroll(&s).unwrap(), expected, "{comment}");
        }
        n += 1;
    }
    assert!(n >= 10);
}
