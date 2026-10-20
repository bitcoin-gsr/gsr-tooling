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
use crate::script::{decode, minimal_push, number, Token};
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
    /// How deep a read must be to be rewritten; `None` if [`anchor_auto`] found not anchoring smallest.
    pub min_depth: Option<u64>,
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
    let stats = Anchored {
        input_bytes: script.len(),
        output_bytes: out.len(),
        min_depth: Some(min_depth),
        rewritten,
        kept,
        witness_items,
    };
    Ok((out, stats))
}

/// The thresholds [`anchor_auto`] tries, besides not anchoring. Reads less than 256 deep take a one-byte depth, so
/// anchoring them rarely pays; on the verifier scripts the best threshold has been 256 or 320.
pub const CANDIDATE_MIN_DEPTHS: [u64; 7] = [192, 224, 256, 288, 320, 384, 512];

/// Each threshold [`anchor_auto`] tried (`None`: not anchoring) with the compressed size it gave.
pub type Tried = Vec<(Option<u64>, usize)>;

/// [`anchor`] with the threshold, from [`CANDIDATE_MIN_DEPTHS`] or none at all, whose result
/// [`compress`](crate::compress) (with the same `protect`) makes smallest; on a tie, the one that rewrites the
/// fewest reads. Also returns what it tried. Compresses up
/// to one candidate per three cores at a time, so it takes a few times as long as compressing once.
pub fn anchor_auto(script: &[u8], protect: usize) -> Result<(Vec<u8>, Anchored, Tried), String> {
    // in order of preference on a tie: fewer rewrites first
    let mut candidates: Vec<(Option<u64>, Vec<u8>, Anchored)> = Vec::new();
    let (_, mut plain) = anchor(script, u64::MAX, protect)?;
    plain.min_depth = None;
    candidates.push((None, script.to_vec(), plain));
    for &t in CANDIDATE_MIN_DEPTHS.iter().rev() {
        let (out, stats) = anchor(script, t, protect)?;
        candidates.push((Some(t), out, stats));
    }
    // compress each distinct script once
    let mut distinct: Vec<usize> = Vec::new();
    let of: Vec<usize> = (0..candidates.len())
        .map(|i| match distinct.iter().position(|&j| candidates[j].1 == candidates[i].1) {
            Some(k) => k,
            None => {
                distinct.push(i);
                distinct.len() - 1
            }
        })
        .collect();
    let at_once = std::thread::available_parallelism().map_or(1, |n| (n.get() / 3).max(1));
    let mut sizes = Vec::with_capacity(distinct.len());
    for batch in distinct.chunks(at_once) {
        let results: Vec<Result<usize, String>> = std::thread::scope(|s| {
            let handles: Vec<_> = batch
                .iter()
                .map(|&i| {
                    let script = &candidates[i].1;
                    s.spawn(move || crate::compress(script, protect).map(|(c, _)| c.len()).map_err(|e| e.to_string()))
                })
                .collect();
            handles.into_iter().map(|h| h.join().expect("compression thread panicked")).collect()
        });
        for r in results {
            sizes.push(r?);
        }
    }
    let tried: Vec<(Option<u64>, usize)> = candidates.iter().zip(&of).map(|(c, &k)| (c.0, sizes[k])).collect();
    let best = (0..candidates.len()).min_by_key(|&i| (sizes[of[i]], i)).expect("candidates");
    let (_, out, stats) = candidates.swap_remove(best);
    Ok((out, stats, tried))
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
