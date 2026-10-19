//! Bottom-anchored addressing: `<d> OP_PICK|OP_ROLL` rewritten as `OP_DEPTH <H − d> OP_SUB OP_PICK|OP_ROLL`, where
//! H is the stack height before the push.
//!
//! A value's depth d changes as the stack grows and shrinks, so reads of it differ and do not become macros. Its
//! index from the bottom, H − d − 1, stays the same while the value stays put, and so does the rewritten read, which
//! [`compress`](crate::compress) can then share. On the RISC Zero verifier the script grows by 11% and compresses to
//! 16% smaller (91,550 → 77,321 bytes), at the cost of an `OP_DEPTH` and an `OP_SUB` per rewritten read.
//!
//! The rewritten read gets the same value only when the real height is H. So a read is rewritten only where
//! [`check`](crate::check)'s stack analysis finds the same height, relative to the witness, on every path; and the
//! script only when every path that runs to the end ends at the same depth, so exactly one witness item count can
//! leave the single item Tapleaf 0xC2 requires. With that count every height is H and both scripts read the same
//! values; with any other count both fail. Unlike `compress`, the script it runs changes, and the proof leaves out
//! what depends on more than the stack depths:
//!
//! - the varops budget: a spend pays two more instructions per rewritten read;
//! - the 8,000,000-byte limit on the stacks' total size: at a rewritten read they hold up to 4 bytes more;
//! - what depends on the script's bytes or length: signatures, the Tapleaf hash, taptree root and output key,
//!   `OP_TX`'s tapscript, witness items and transaction weight (`--protect` keeps a prefix in place for scripts
//!   that read their own bytes at fixed offsets);
//! - which instruction a failing witness fails at.

use crate::check::{analyze, Analysis};
use crate::opcodes::{Class, Opcode};
use crate::script::{decode, Token};
use crate::{Decoding, Severity};

/// The most items the stack and altstack may hold together.
const MAX_STACK_SIZE: i64 = 32_768;
const OP_DEPTH: u8 = 0x74;
const OP_SUB: u8 = 0x94;

/// What [`anchor`] did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Anchored {
    pub input_bytes: usize,
    pub output_bytes: usize,
    /// Reads at least `min_depth` deep that were rewritten.
    pub rewritten: usize,
    /// Reads at least `min_depth` deep left as they were: in the protected prefix, or where the height is not one
    /// value.
    pub kept: usize,
    /// The only witness item count with which the script can succeed.
    pub witness_items: u64,
}

/// Rewrites the main script's reads `<d> OP_PICK|OP_ROLL` with d at least `min_depth` to address from the stack
/// bottom, leaving the main script's first `protect` bytes as they are. Fails, saying why, when it cannot prove
/// that the rewrite keeps the witnesses the script accepts.
pub fn anchor(script: &[u8], min_depth: u64, protect: usize) -> Result<(Vec<u8>, Anchored), String> {
    let (witness_items, analysis) = provable(script)?;
    let d = decode(script).map_err(|e| e.to_string())?;
    let main = &script[d.main_offset..];
    let mut out = script[..d.main_offset].to_vec();
    let (mut copied, mut rewritten, mut kept) = (0, 0, 0);
    for pair in d.main.windows(2) {
        let [(Token::Op(push), p), (Token::Op(read), _)] = pair else { continue };
        if !matches!(read[0], 0x79 | 0x7a) {
            continue;
        }
        // only minimal pushes: whether a non-minimal operand is accepted is not the rewrite's to change
        let Some(depth) = number(push).filter(|&n| minimal_push(n) == *push) else { continue };
        if depth < min_depth {
            continue;
        }
        let height = analysis.heights.get(&(d.main_offset + p)).copied().flatten();
        let target = height.and_then(|(delta, alt)| {
            let h = witness_items as i64 + delta;
            // the original read fails unless depth < h; the rewrite briefly holds two items more
            let fits = u64::try_from(h).is_ok_and(|h| depth < h) && h + 2 + alt <= MAX_STACK_SIZE;
            (*p >= protect && fits).then(|| h as u64 - depth)
        });
        let Some(index) = target else {
            kept += 1;
            continue;
        };
        out.extend_from_slice(&main[copied..*p]);
        out.push(OP_DEPTH);
        out.extend_from_slice(&minimal_push(index));
        out.push(OP_SUB);
        copied = p + push.len();
        rewritten += 1;
    }
    out.extend_from_slice(&main[copied..]);
    // the rewritten script must check out the same way
    let (after, _) = provable(&out).map_err(|e| format!("the rewritten script does not check out: {e}"))?;
    if after != witness_items {
        return Err(format!("the rewritten script takes {after} witness items, not {witness_items}"));
    }
    let stats = Anchored { input_bytes: script.len(), output_bytes: out.len(), rewritten, kept, witness_items };
    Ok((out, stats))
}

/// The only witness item count with which the script can succeed, if the stack analysis proves there is one, and
/// the analysis.
fn provable(script: &[u8]) -> Result<(u64, Analysis), String> {
    let (report, analysis) = analyze(script);
    if report.decoding != Decoding::WellFormed {
        return Err(format!("decoding: {}", report.decoding.id()));
    }
    let errors = report.count(Severity::Error);
    if errors > 0 {
        return Err(format!("gsr check reports {errors} errors"));
    }
    if let Some(s) = &report.stack_analysis_stopped {
        return Err(format!("the stack analysis stopped at byte {}: {}", s.offset, s.reason));
    }
    if analysis.codeseparator {
        return Err("OP_CODESEPARATOR: the rewrite would move the positions signatures commit to".into());
    }
    let mut ends = analysis.final_deltas.clone();
    ends.sort_unstable();
    ends.dedup();
    match ends[..] {
        [delta] if delta <= 1 => Ok(((1 - delta) as u64, analysis)),
        [_] | [] => Err("no witness item count ends with one item".into()),
        _ => Err(format!(
            "paths end at {} different stack depths, so more than one witness item count can succeed",
            ends.len()
        )),
    }
}

/// The number a push instruction pushes, if it fits 64 bits.
fn number(push: &[u8]) -> Option<u64> {
    let data = match Opcode::from_u8(push[0]).class() {
        Class::PushNum(n) => return Some(n.into()),
        Class::PushBytes(n) => &push[push.len() - n as usize..],
        Class::PushData(width) => &push[1 + width as usize..],
        _ => return None,
    };
    data.iter().skip(8).all(|&b| b == 0).then(|| data.iter().take(8).rev().fold(0, |n, &b| n << 8 | b as u64))
}

/// The minimal push of `n`: `OP_0`–`OP_16`, else its little-endian bytes without trailing zeros. The single byte
/// 0x81 takes a direct push, as `OP_1NEGATE` is an OP_SUCCESSx in Tapleaf 0xC2.
fn minimal_push(n: u64) -> Vec<u8> {
    match n {
        0 => vec![0x00],
        1..=16 => vec![0x50 + n as u8],
        _ => {
            let len = 8 - n.leading_zeros() as usize / 8;
            [&[len as u8][..], &n.to_le_bytes()[..len]].concat()
        }
    }
}
