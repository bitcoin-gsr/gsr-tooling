//! Tools for Tapleaf 0xC2 (GSR) scripts.
//!
//! - [`opcodes`]: what each byte means as an instruction (names, classes, stack effects);
//! - [`check`]: static checks for consensus errors, policy warnings and lints, without executing the script;
//! - [`compress`], [`unroll`], [`info`], [`lower_bounds`]: macro compression and its measures;
//! - [`anchor`]: bottom-anchored stack addressing, a rewrite that makes deep reads repeat so they compress;
//! - [`disasm`]: a readable listing; [`attribute`]: a compressed script's bytes by labelled part of its source;
//!   [`near_duplicates`]: sequences that would compress if a pushed number agreed.
//!
//! # Macro compression
//!
//! [`compress`] shrinks a script by searching for a small reusable-macro grammar (`OP_MACRO` declarations,
//! `OP_CALLMACRO` references) that unrolls to exactly the same script. The committed size is minimized exactly:
//! every declaration header, every CompactSize index (one byte below 253, three above) and every body is counted.
//! The problem statement, the cost model and results are in `docs/macro-optimization.md`.
//!
//! The search, per configuration:
//!
//! - **irr**, iterative repeat replacement: the repeat (any length, non-overlapping occurrences, in the main
//!   script or any body) whose replacement saves the most bytes becomes a new macro;
//! - **mgp**, minimal grammar parsing: every body and the main script are re-parsed optimally with the current
//!   macros as the dictionary, macros that do not pay for themselves are removed, until the size stops falling;
//! - **loop** alternates the two; **ls**, local search, then removes single macros when re-parsing without them
//!   shrinks the script.
//!
//! The declaration order puts a dependency-closed set of at most 253 macros with the most references first (a
//! Lagrangian minimum-cut closure, filled greedily), so they get one-byte indices. Six configurations (starting
//! from the script's own macros or from the unrolled script, with a minimum saving of 0, 1 or 2 bytes per new
//! macro) run in parallel and the smallest result is kept.

mod anchor;
mod attribute;
mod bound;
mod check;
mod disasm;
mod grammar;
mod irr;
mod near;
pub mod opcodes;
mod order;
mod parse;
mod script;
mod suffix;

use std::fmt;

pub use anchor::{anchor, anchor_auto, Anchored, Tried, CANDIDATE_MIN_DEPTHS};
pub use attribute::{attribute, Attribution, LabelBytes, LabelledRange};
pub use check::{check, Decoding, Diagnostic, Report, Rule, Severity};
pub use disasm::{disasm, instruction_text};
pub use grammar::Start;
use grammar::{encode, evaluate, from_script, in_declaration_order, Grammar};
pub use near::{near_duplicates, NearDuplicate, Varying};
use script::{decode, Token};

/// A script that is not well formed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// An instruction, CompactSize or declaration runs past the end of the script (at this offset).
    Truncated(usize),
    NonCanonicalCompactSize(usize),
    /// `OP_MACRO` after the declarations.
    MisplacedDeclaration(usize),
    /// A reference to a declaration that does not precede it.
    UndeclaredMacro {
        offset: usize,
        index: usize,
    },
}

impl Error {
    fn offset_by(self, base: usize) -> Self {
        match self {
            Error::Truncated(o) => Error::Truncated(base + o),
            Error::NonCanonicalCompactSize(o) => Error::NonCanonicalCompactSize(base + o),
            Error::MisplacedDeclaration(o) => Error::MisplacedDeclaration(base + o),
            Error::UndeclaredMacro { offset, index } => Error::UndeclaredMacro { offset: base + offset, index },
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated(o) => write!(f, "truncated at byte {o}"),
            Error::NonCanonicalCompactSize(o) => write!(f, "non-canonical CompactSize at byte {o}"),
            Error::MisplacedDeclaration(o) => write!(f, "OP_MACRO after the declarations at byte {o}"),
            Error::UndeclaredMacro { offset, index } => {
                write!(f, "reference to undeclared macro {index} at byte {offset}")
            }
        }
    }
}

impl std::error::Error for Error {}

/// What [`compress`] found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stats {
    pub input_bytes: usize,
    pub output_bytes: usize,
    pub declarations: usize,
    /// Length of the declarations: the offset of the main script.
    pub decl_len: usize,
    /// The configuration that won.
    pub start: Start,
    pub min_saving: i64,
}

/// The six configurations: (start, minimum saving of a new macro in bytes). Each wins on some script.
const CONFIGS: [(Start, i64); 6] = [
    (Start::Plain, 0),
    (Start::Inline, 0),
    (Start::Plain, 1),
    (Start::Inline, 1),
    (Start::Plain, 2),
    (Start::Inline, 2),
];
const ROUNDS: usize = 30;

fn search(mut g: Grammar, min_saving: i64) -> Grammar {
    irr::irr(&mut g, min_saving, usize::MAX);
    g = parse::mgp(&g, ROUNDS);
    let mut cur = evaluate(&g).total;
    for _ in 0..ROUNDS {
        // alternate repeat replacement and re-parsing until neither helps
        let mut h = g.clone();
        irr::irr(&mut h, min_saving, usize::MAX);
        h = parse::mgp(&h, ROUNDS);
        let t = evaluate(&h).total;
        if t >= cur {
            break;
        }
        g = h;
        cur = t;
    }
    parse::local_search(g, ROUNDS)
}

/// A smaller script that unrolls to exactly `script`, and what was found.
///
/// Main-script bytes below `protect` stay literal at their offsets from the start of the main script, up to the
/// first macro reference among them: for scripts that read their own bytes at fixed offsets. The result does not
/// depend on the values of the protected instructions.
pub fn compress(script: &[u8], protect: usize) -> Result<(Vec<u8>, Stats), Error> {
    let d = decode(script)?;
    let results: Vec<(Vec<u8>, usize)> = std::thread::scope(|s| {
        let handles: Vec<_> = CONFIGS
            .iter()
            .map(|&(start, min_saving)| {
                let d = &d;
                s.spawn(move || {
                    let (terms, g) = from_script(d, start, protect);
                    encode(&terms, &in_declaration_order(&search(g, min_saving)))
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().expect("search thread panicked")).collect()
    });
    let k = (0..CONFIGS.len()).min_by_key(|&i| (results[i].0.len(), i)).unwrap();
    let (out, decl_len) = results.into_iter().nth(k).unwrap();
    let od = decode(&out).expect("the encoder emits well-formed scripts");
    assert!(od.unroll() == d.unroll(), "unrolled scripts differ");
    assert!(protected_prefix(&d, protect) == protected_prefix(&od, protect), "protected bytes moved");
    let stats = Stats {
        input_bytes: script.len(),
        output_bytes: out.len(),
        declarations: od.bodies.len(),
        decl_len,
        start: CONFIGS[k].0,
        min_saving: CONFIGS[k].1,
    };
    Ok((out, stats))
}

/// The main-script instructions that start below `protect`, up to the first reference.
fn protected_prefix<'a>(d: &script::Decoded<'a>, protect: usize) -> Vec<&'a [u8]> {
    d.main
        .iter()
        .take_while(|&&(t, p)| p < protect && matches!(t, Token::Op(_)))
        .map(|&(t, _)| match t {
            Token::Op(b) => b,
            Token::Call(_) => unreachable!(),
        })
        .collect()
}

/// The script the interpreter runs: every macro reference replaced by its body.
pub fn unroll(script: &[u8]) -> Result<Vec<u8>, Error> {
    Ok(decode(script)?.unroll())
}

/// A script's layout and the varops its macros add.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub bytes: usize,
    pub declarations: usize,
    /// Length of the declarations: the offset of the main script.
    pub decl_len: usize,
    /// Length of the script the interpreter runs. This and the counts below saturate at `u64::MAX`.
    pub unrolled_bytes: u64,
    /// Instructions substituted from bodies when unrolling.
    pub substituted: u64,
    /// References visited when unrolling.
    pub references: u64,
    /// BIP 440: 300 per substituted instruction and per reference, plus the write cost of the unrolled script
    /// when there are declarations.
    pub unrolling_charge: u64,
}

pub fn info(script: &[u8]) -> Result<Info, Error> {
    let d = decode(script)?;
    // (instructions, references, bytes) of each body's full expansion; bodies only use earlier ones. The sums
    // saturate: nested references can unroll to more than 2^64 bytes.
    let mut totals: Vec<(u64, u64, u64)> = Vec::with_capacity(d.bodies.len());
    for body in &d.bodies {
        let t = body.iter().fold((0u64, 0u64, 0u64), |(n, r, b), &(t, _)| match t {
            Token::Op(bytes) => (n.saturating_add(1), r, b.saturating_add(bytes.len() as u64)),
            Token::Call(k) => (
                n.saturating_add(totals[k].0),
                r.saturating_add(1).saturating_add(totals[k].1),
                b.saturating_add(totals[k].2),
            ),
        });
        totals.push(t);
    }
    let (mut s, mut r, mut l) = (0u64, 0u64, 0u64);
    for &(t, _) in &d.main {
        match t {
            Token::Op(bytes) => l = l.saturating_add(bytes.len() as u64),
            Token::Call(k) => {
                s = s.saturating_add(totals[k].0);
                r = r.saturating_add(1).saturating_add(totals[k].1);
                l = l.saturating_add(totals[k].2);
            }
        }
    }
    let write =
        if d.bodies.is_empty() { 0 } else { 7u64.saturating_mul(l.div_ceil(8).saturating_mul(8)).saturating_add(800) };
    Ok(Info {
        bytes: script.len(),
        declarations: d.bodies.len(),
        decl_len: d.main_offset,
        unrolled_bytes: l,
        substituted: s,
        references: r,
        unrolling_charge: s.saturating_add(r).saturating_mul(300).saturating_add(write),
    })
}

/// Lower bounds on the committed size of any macro encoding of a script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bounds {
    /// Each distinct instruction must appear at least once.
    pub distinct_instruction_bytes: u64,
    /// The cheapest LZ77-style parse with 2-byte copies (ignores declaration headers).
    pub lz: u64,
}

pub fn lower_bounds(script: &[u8]) -> Result<Bounds, Error> {
    let (terms, g) = from_script(&decode(script)?, Start::Inline, 0);
    Ok(Bounds {
        distinct_instruction_bytes: terms.iter().map(|t| t.len() as u64).sum(),
        lz: bound::lz_bound(&g) as u64,
    })
}
