//! Near-duplicates: instruction sequences that repeat except for one or a few pushed numbers, such as a stack depth
//! or a byte offset that counts up. Exact repeats become macros; these do not until the numbers agree, which a
//! generator can often arrange (address from the stack bottom, compute the offset on the stack).
//!
//! The script's bodies and main script, as committed, are searched with every number push (up to 8 bytes) as a
//! wildcard, by suffix array. For a repeat whose occurrences differ in at most `max_varying` of their numbers and
//! share at least 6 other bytes, the
//! estimated saving if they were identical is that of one macro for the whole sequence, less what macros for the
//! parts between the varying numbers already save: with `k` non-overlapping occurrences and a reference of 2 bytes,
//! a sequence of `b` bytes saves `k·(b − 2) − (b + 2)`. It ignores other occurrences of the parts and what the
//! numbers would cost to make equal, so it ranks rather than predicts.

use std::collections::HashMap;

use crate::disasm::instruction_text;
use crate::script::{decode, number, push_data, Token};
use crate::suffix::{lcp_array, suffix_array};
use crate::Error;

/// Shortest sequence considered, in instructions.
const MIN_LEN: usize = 3;
/// The fewest bytes the occurrences must share besides the varying numbers.
const MIN_SHARED: i64 = 6;
const WILDCARD: u32 = 0;

/// Instructions that repeat except for some pushed numbers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NearDuplicate {
    /// The instructions as [`disasm`](crate::disasm) lists them, the varying numbers as `$1`, `$2`, ...
    pub pattern: Vec<String>,
    /// Byte offset of each non-overlapping occurrence in the script, in order.
    pub occurrences: Vec<usize>,
    /// Bytes of the first occurrence.
    pub bytes: usize,
    /// Bytes of all occurrences.
    pub total_bytes: usize,
    pub varying: Vec<Varying>,
    /// Estimated bytes saved if the occurrences were identical.
    pub saving: i64,
}

/// A number that differs between the occurrences.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Varying {
    /// Its instruction's index in the pattern.
    pub index: usize,
    pub min: u64,
    pub max: u64,
    pub distinct: usize,
    /// The difference between consecutive occurrences, if it is always the same.
    pub step: Option<i64>,
    /// The instruction after it, if any (`PICK` or `ROLL`: a stack depth).
    pub before: Option<String>,
}

/// The `top` near-duplicates with the largest estimated saving, at most `max_varying` numbers differing, not
/// mostly overlapping each other.
pub fn near_duplicates(script: &[u8], max_varying: usize, top: usize) -> Result<Vec<NearDuplicate>, Error> {
    let d = decode(script)?;
    let sequences =
        d.bodies.iter().enumerate().map(|(k, b)| (b, d.declarations[k].body)).chain([(&d.main, d.main_offset)]);
    // the concatenated sequences: symbol, instruction bytes and script offset per position; unique separators
    let mut ids: HashMap<Vec<u8>, u32> = HashMap::new();
    let mut a: Vec<u32> = Vec::new();
    let mut toks: Vec<Option<(&[u8], usize)>> = Vec::new();
    let mut seps = 0u32;
    for (seq, base) in sequences {
        for &(t, p) in seq {
            let (sym, bytes): (u32, &[u8]) = match t {
                Token::Op(bytes) if is_number(bytes) => (WILDCARD, bytes),
                Token::Op(bytes) => {
                    let n = ids.len() as u32 + 1;
                    (*ids.entry(bytes.to_vec()).or_insert(n), bytes)
                }
                Token::Call(k) => {
                    let n = ids.len() as u32 + 1;
                    let key = [&[0xd1][..], &(k as u64).to_le_bytes()].concat();
                    (*ids.entry(key).or_insert(n), &script[base + p..base + p + call_len(k)])
                }
            };
            a.push(sym);
            toks.push(Some((bytes, base + p)));
        }
        seps += 1;
        a.push(u32::MAX - seps);
        toks.push(None);
    }
    let n = a.len();
    let mut size = vec![0usize; n + 1];
    for i in 0..n {
        size[i + 1] = size[i] + toks[i].map_or(0, |(b, _)| b.len());
    }
    let sa = suffix_array(&a);
    let lcp = lcp_array(&a, &sa);

    let mut found: Vec<(NearDuplicate, Vec<usize>, usize)> = Vec::new();
    // LCP intervals bottom-up: (length, left bound)
    let mut stack: Vec<(usize, usize)> = vec![(0, 0)];
    for i in 1..=n {
        let h = if i < n { lcp[i] } else { 0 };
        let mut lb = i - 1;
        while stack.last().is_some_and(|&(l, _)| l > h) {
            let (l, left) = stack.pop().unwrap();
            lb = left;
            if l >= MIN_LEN {
                let mut at: Vec<usize> = sa[left..i].to_vec();
                at.sort_unstable();
                if let Some(c) = candidate(&a, &toks, &size, &at, l, max_varying) {
                    found.push(c);
                }
            }
        }
        if stack.last().map_or(true, |&(l, _)| l < h) {
            stack.push((h, lb));
        }
    }

    // the largest savings first, skipping those mostly covered by one already taken
    found.sort_by(|x, y| y.0.saving.cmp(&x.0.saving).then(x.0.occurrences.cmp(&y.0.occurrences)));
    let mut covered = vec![false; n];
    let mut out = Vec::new();
    for (dup, starts, len) in found {
        if out.len() == top {
            break;
        }
        let total = starts.len() * len;
        let fresh = starts.iter().flat_map(|&s| s..s + len).filter(|&i| !covered[i]).count();
        if 2 * fresh <= total {
            continue;
        }
        for &s in &starts {
            covered[s..s + len].fill(true);
        }
        out.push(dup);
    }
    Ok(out)
}

/// The near-duplicate among the occurrences `at` (sorted) of a pattern of `len` symbols, with the positions of the
/// occurrences taken and the length; `None` if there are fewer than two that do not overlap, none or too many
/// numbers differ, or it saves nothing.
fn candidate(
    a: &[u32],
    toks: &[Option<(&[u8], usize)>],
    size: &[usize],
    at: &[usize],
    len: usize,
    max_varying: usize,
) -> Option<(NearDuplicate, Vec<usize>, usize)> {
    let start = at[0];
    let wild: Vec<usize> = (0..len).filter(|&j| a[start + j] == WILDCARD).collect();
    if wild.is_empty() {
        return None;
    }
    let mut starts: Vec<usize> = Vec::new();
    for &s in at {
        if starts.last().map_or(true, |&last| s >= last + len) {
            starts.push(s);
        }
    }
    let k = starts.len();
    if k < 2 {
        return None;
    }
    let value = |s: usize, j: usize| number(toks[s + j].expect("not a separator").0).expect("a number push");
    let varying: Vec<usize> =
        wild.iter().copied().filter(|&j| starts.iter().any(|&s| value(s, j) != value(start, j))).collect();
    if varying.is_empty() || varying.len() > max_varying {
        return None;
    }
    let bytes = |s: usize, from: usize, to: usize| (size[s + to] - size[s + from]) as i64;
    let shared = bytes(start, 0, len) - varying.iter().map(|&j| bytes(start, j, j + 1)).sum::<i64>();
    if shared < MIN_SHARED {
        return None;
    }
    let macro_saving = |b: i64| (k as i64 * (b - 2) - (b + 2)).max(0);
    let total: i64 = starts.iter().map(|&s| bytes(s, 0, len)).sum();
    let first = bytes(start, 0, len);
    let identical = total - 2 * k as i64 - (first + 2);
    // the parts between the varying numbers, the same in every occurrence
    let mut parts = 0;
    let mut from = 0;
    for &j in varying.iter().chain([&len]) {
        if j > from {
            parts += macro_saving(bytes(start, from, j));
        }
        from = j + 1;
    }
    // or macros for the occurrences whose numbers already agree
    let mut groups: Vec<(Vec<u64>, usize, i64)> = Vec::new();
    for &s in &starts {
        let key: Vec<u64> = varying.iter().map(|&j| value(s, j)).collect();
        match groups.iter_mut().find(|g| g.0 == key) {
            Some(g) => g.1 += 1,
            None => groups.push((key, 1, bytes(s, 0, len))),
        }
    }
    let agreeing: i64 = groups.iter().map(|&(_, m, b)| (m as i64 * (b - 2) - (b + 2)).max(0)).sum();
    let saving = identical - parts.max(agreeing);
    if saving <= 0 {
        return None;
    }
    let pattern: Vec<String> = (0..len)
        .map(|j| match varying.iter().position(|&v| v == j) {
            Some(v) => format!("${}", v + 1),
            None => text(toks[start + j].unwrap().0),
        })
        .collect();
    let varying = varying
        .iter()
        .map(|&j| {
            let values: Vec<u64> = starts.iter().map(|&s| value(s, j)).collect();
            let mut distinct = values.clone();
            distinct.sort_unstable();
            distinct.dedup();
            let step = values[1] as i64 - values[0] as i64;
            let constant_step = values.windows(2).all(|w| w[1] as i64 - w[0] as i64 == step);
            Varying {
                index: j,
                min: distinct[0],
                max: *distinct.last().unwrap(),
                distinct: distinct.len(),
                step: constant_step.then_some(step),
                before: pattern.get(j + 1).cloned(),
            }
        })
        .collect();
    let dup = NearDuplicate {
        pattern,
        occurrences: starts.iter().map(|&s| toks[s].unwrap().1).collect(),
        bytes: first as usize,
        total_bytes: total as usize,
        varying,
        saving,
    };
    Some((dup, starts, len))
}

/// A push of a number of up to 8 bytes (`OP_0`–`OP_16` included).
fn is_number(instruction: &[u8]) -> bool {
    number(instruction).is_some() && push_data(instruction).map_or(true, |d| d.len() <= 8)
}

/// An instruction as `disasm` lists it, a reference as `call<k>`.
fn text(bytes: &[u8]) -> String {
    match bytes {
        [0xd1, ..] => match bytes.len() {
            2 => format!("call{}", bytes[1]),
            _ => format!("call{}", bytes[2..].iter().rev().fold(0u64, |n, &b| n << 8 | b as u64)),
        },
        _ => instruction_text(bytes, false),
    }
}

fn call_len(k: usize) -> usize {
    1 + crate::script::compact_len(k as u64)
}
