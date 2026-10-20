//! Which parts of a script its committed bytes pay for: a compressed script's bytes attributed to labelled byte
//! ranges of the plain script it was made from, through `gsr anchor`'s rewrites.
//!
//! Every instruction of the plain script, unrolled, takes the label of the shortest range containing its offset or,
//! failing that, the offset of the innermost reference it was expanded through that has one. The compressed script
//! must unroll to the same instructions, except that reads `<d> OP_PICK|OP_ROLL` may be anchored
//! (`OP_DEPTH <k> OP_SUB OP_PICK|OP_ROLL`, which takes the push's label). Then:
//!
//! - main-script instructions count for their label, and a reference for the labels of what it unrolls to, in
//!   proportion to their unrolled bytes;
//! - each declaration counts for the labels of everything its expansions unroll to, wherever they occur, in
//!   proportion to their unrolled bytes. A declaration that only one label uses is that label's alone.

use crate::script::{compact_len, decode, number, push_data, Decoded, Token};

/// A labelled range of the plain script's bytes, `start..end`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LabelledRange {
    pub start: usize,
    pub end: usize,
    pub label: String,
}

/// What one label pays for in the compressed script. Shares split in proportion are fractional.
#[derive(Clone, Debug, PartialEq)]
pub struct LabelBytes {
    /// `None` for what no range covers.
    pub label: Option<String>,
    /// Plain-script bytes with this label (the shortest range containing them).
    pub plain_bytes: u64,
    /// Bytes of the compressed script, unrolled, with this label.
    pub unrolled_bytes: u64,
    /// Share of the compressed main script.
    pub main_bytes: f64,
    /// Share of the declarations it uses.
    pub declaration_bytes: f64,
    /// Declarations it uses.
    pub declarations: usize,
    /// Bytes of the declarations only it uses.
    pub exclusive_declaration_bytes: u64,
}

/// A compressed script's bytes by label.
#[derive(Clone, Debug, PartialEq)]
pub struct Attribution {
    pub bytes: usize,
    pub main_bytes: usize,
    pub declaration_bytes: usize,
    /// The labels in the order of their first range, then the unlabelled bytes if there are any.
    pub labels: Vec<LabelBytes>,
}

/// Attributes the bytes of `compressed` to `ranges` of `plain`, the script it was made from with `gsr anchor`
/// and `gsr compress` (either or both).
pub fn attribute(compressed: &[u8], plain: &[u8], ranges: &[LabelledRange]) -> Result<Attribution, String> {
    let p = decode(plain).map_err(|e| format!("plain script: {e}"))?;
    let c = decode(compressed).map_err(|e| format!("compressed script: {e}"))?;
    let (names, of_offset) = label_map(plain.len(), ranges)?;
    let unlabelled = names.len();
    let mut out: Vec<LabelBytes> = names.iter().map(|n| LabelBytes::new(Some(n.clone()))).collect();
    out.push(LabelBytes::new(None));
    for &l in &of_offset {
        out[l.map_or(unlabelled, |l| l as usize)].plain_bytes += 1;
    }

    // the plain script unrolled: each instruction with its label
    let mut plain_ops: Vec<(&[u8], usize)> = Vec::new();
    unroll_labelled(&p, &of_offset, unlabelled, &mut plain_ops);

    // the compressed script unrolled in step with it
    let mut walk = Walk {
        d: &c,
        plain: &plain_ops,
        at: 0,
        pending: None,
        open: Vec::new(),
        usage: vec![vec![0; out.len()]; c.bodies.len()],
        unrolled: vec![0; out.len()],
    };
    let mut main_bytes = vec![0f64; out.len()];
    for &(t, _) in &c.main {
        match t {
            Token::Op(bytes) => {
                let l = walk.op(bytes)?;
                main_bytes[l] += bytes.len() as f64;
            }
            Token::Call(k) => {
                let before = walk.unrolled.clone();
                walk.call(k)?;
                let spread: Vec<u64> = walk.unrolled.iter().zip(&before).map(|(a, b)| a - b).collect();
                share(&mut main_bytes, &spread, (1 + compact_len(k as u64)) as f64);
            }
        }
    }
    if walk.at != plain_ops.len() || walk.pending.is_some() {
        return Err(format!(
            "the compressed script unrolls to fewer instructions than the plain script ({} of {})",
            walk.at,
            plain_ops.len()
        ));
    }
    for (l, o) in out.iter_mut().enumerate() {
        o.unrolled_bytes = walk.unrolled[l];
        o.main_bytes = main_bytes[l];
    }
    for (k, usage) in walk.usage.iter().enumerate() {
        let span = c.declarations[k];
        let size = span.end - span.at;
        let users: Vec<usize> = (0..usage.len()).filter(|&l| usage[l] > 0).collect();
        let mut decl = vec![0f64; out.len()];
        share(&mut decl, usage, size as f64);
        for &l in &users {
            out[l].declaration_bytes += decl[l];
            out[l].declarations += 1;
            if users.len() == 1 {
                out[l].exclusive_declaration_bytes += size as u64;
            }
        }
    }
    let last = out.last().unwrap();
    if last.plain_bytes == 0 && last.unrolled_bytes == 0 {
        out.pop();
    }
    Ok(Attribution {
        bytes: compressed.len(),
        main_bytes: compressed.len() - c.main_offset,
        declaration_bytes: c.main_offset,
        labels: out,
    })
}

/// The distinct labels in order of first appearance, and each plain-script byte's label: the shortest range
/// containing it.
fn label_map(len: usize, ranges: &[LabelledRange]) -> Result<(Vec<String>, Vec<Option<u32>>), String> {
    let mut names: Vec<String> = Vec::new();
    let mut ids = Vec::with_capacity(ranges.len());
    for r in ranges {
        if r.start >= r.end || r.end > len {
            return Err(format!(
                "range {}..{} ({}) is empty or past the plain script's {len} bytes",
                r.start, r.end, r.label
            ));
        }
        let id = names.iter().position(|n| *n == r.label).unwrap_or_else(|| {
            names.push(r.label.clone());
            names.len() - 1
        });
        ids.push(id as u32);
    }
    let mut order: Vec<usize> = (0..ranges.len()).collect();
    // longest first, so shorter ranges overwrite them
    order.sort_by_key(|&i| std::cmp::Reverse(ranges[i].end - ranges[i].start));
    let mut of_offset = vec![None; len];
    for i in order {
        of_offset[ranges[i].start..ranges[i].end].fill(Some(ids[i]));
    }
    Ok((names, of_offset))
}

/// Appends the plain script's instructions, unrolled, with their labels.
fn unroll_labelled<'a>(
    d: &Decoded<'a>,
    of_offset: &[Option<u32>],
    unlabelled: usize,
    out: &mut Vec<(&'a [u8], usize)>,
) {
    // (tokens, offset of the sequence in the script, label of the reference that expanded it)
    let mut stack = vec![(&d.main[..], d.main_offset, None)];
    while let Some(top) = stack.last_mut() {
        let Some((&(t, p), rest)) = top.0.split_first() else {
            stack.pop();
            continue;
        };
        top.0 = rest;
        let (base, outer) = (top.1, top.2);
        let here = of_offset[base + p].or(outer);
        match t {
            Token::Op(bytes) => out.push((bytes, here.map_or(unlabelled, |l| l as usize))),
            Token::Call(k) => stack.push((&d.bodies[k][..], d.declarations[k].body, here)),
        }
    }
}

impl LabelBytes {
    fn new(label: Option<String>) -> Self {
        LabelBytes {
            label,
            plain_bytes: 0,
            unrolled_bytes: 0,
            main_bytes: 0.0,
            declaration_bytes: 0.0,
            declarations: 0,
            exclusive_declaration_bytes: 0,
        }
    }
}

struct Walk<'a, 'b> {
    d: &'b Decoded<'a>,
    plain: &'b [(&'a [u8], usize)],
    /// The next plain instruction.
    at: usize,
    /// Inside an anchored read: the instructions of `OP_DEPTH <k> OP_SUB` still to come, and their label.
    pending: Option<(u8, usize)>,
    /// The declarations being expanded.
    open: Vec<usize>,
    /// Per declaration, the unrolled bytes of its expansions by label.
    usage: Vec<Vec<u64>>,
    /// Unrolled bytes by label.
    unrolled: Vec<u64>,
}

impl Walk<'_, '_> {
    fn call(&mut self, k: usize) -> Result<(), String> {
        self.open.push(k);
        let d = self.d;
        for &(t, _) in &d.bodies[k] {
            match t {
                Token::Op(bytes) => {
                    self.op(bytes)?;
                }
                Token::Call(j) => self.call(j)?,
            }
        }
        self.open.pop();
        Ok(())
    }

    /// Matches the next compressed instruction, unrolled, with the plain script -> its label.
    fn op(&mut self, bytes: &[u8]) -> Result<usize, String> {
        let label = match self.pending {
            // the index push, then OP_SUB
            Some((2, label)) if push_data(bytes).is_some() || number(bytes).is_some() => {
                self.pending = Some((1, label));
                label
            }
            Some((1, label)) if bytes == [0x94] => {
                self.pending = None;
                self.at += 1;
                label
            }
            Some(_) => return Err(self.mismatch()),
            None => {
                let Some(&(expected, label)) = self.plain.get(self.at) else {
                    return Err("the compressed script unrolls to more instructions than the plain script".into());
                };
                if bytes == expected {
                    self.at += 1;
                } else if bytes == [0x74] && self.anchorable() {
                    self.pending = Some((2, label));
                } else {
                    return Err(self.mismatch());
                }
                label
            }
        };
        let n = bytes.len() as u64;
        self.unrolled[label] += n;
        for &k in &self.open {
            self.usage[k][label] += n;
        }
        Ok(label)
    }

    /// Whether the next plain instructions are a number push and `OP_PICK` or `OP_ROLL`.
    fn anchorable(&self) -> bool {
        let next = self.plain.get(self.at + 1).map(|&(b, _)| b);
        number(self.plain[self.at].0).is_some() && matches!(next, Some([0x79]) | Some([0x7a]))
    }

    fn mismatch(&self) -> String {
        format!(
            "the compressed script does not unroll to the plain script or an anchoring of it: they differ at the \
             plain script's unrolled instruction {}",
            self.at
        )
    }
}

fn share(into: &mut [f64], weights: &[u64], amount: f64) {
    let total: u64 = weights.iter().sum();
    if total == 0 {
        return;
    }
    for (x, &w) in into.iter_mut().zip(weights) {
        *x += amount * w as f64 / total as f64;
    }
}
