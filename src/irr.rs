//! Iterative repeat replacement, most compressive.
//!
//! Repeatedly replaces the repeat with the largest exact saving (all lengths, non-overlapping occurrences, the
//! declaration and the CompactSize index included) by a new rule. A new rule is priced as hot (2-byte reference,
//! displacing the least-used hot rule) or cold (4-byte reference), whichever saves more.

use crate::grammar::{count_uses, Grammar, Sym};
use crate::order::HOT;
use crate::script::compact_len;
use crate::suffix::{lcp_array, suffix_array};

struct Cand {
    ub: i64,
    len: usize,
    lb: usize,
    rb: usize,
}

/// Adds rules while one saves more than `min_saving` bytes; returns how many.
pub fn irr(g: &mut Grammar, min_saving: i64, max_rules: usize) -> usize {
    let mut added = 0;
    loop {
        let r_count = g.rules.len();
        if r_count >= max_rules {
            break;
        }
        // current reference costs: hot if among the HOT most used
        let uses = count_uses(g);
        let mut refcost = vec![4i64; r_count];
        let mut k_hot = 0i64;
        {
            let mut idx: Vec<usize> = (0..r_count).collect();
            idx.sort_by_key(|&r| std::cmp::Reverse(uses[r])); // stable
            for &r in idx.iter().take(HOT) {
                refcost[r] = 2;
            }
            if r_count >= HOT {
                k_hot = uses[idx[HOT - 1]];
            }
        }
        let new_sym = (g.t + r_count) as Sym;
        // all sequences, each followed by a unique separator above the new rule's symbol
        let mut a: Vec<Sym> = Vec::new();
        let mut sep = new_sym + 1;
        for s in std::iter::once(&g.main).chain(&g.rules) {
            a.extend_from_slice(s);
            a.push(sep);
            sep += 1;
        }
        let n = a.len();
        let mut prefix = vec![0i64; n + 1];
        for i in 0..n {
            let x = a[i];
            let c = if x < new_sym {
                if g.is_rule(x) {
                    refcost[g.rule(x)]
                } else {
                    g.tcost[x as usize]
                }
            } else {
                0
            };
            prefix[i + 1] = prefix[i] + c;
        }
        let sa = suffix_array(&a);
        let lcp = lcp_array(&a, &sa);
        let score = |k: i64, w: i64| -> i64 {
            let h = 1 + compact_len(w as u64) as i64;
            let cold = k * (w - 4) - (w + h);
            let hot = if r_count < HOT {
                k * (w - 2) - (w + h)
            } else if k > k_hot {
                k * (w - 2) - (w + h) - 2 * k_hot
            } else {
                i64::MIN
            };
            cold.max(hot)
        };
        // LCP intervals
        let mut cands = Vec::new();
        let mut report = |len: usize, lb: usize, rb: usize| {
            if len < 1 || rb <= lb {
                return;
            }
            let p = sa[lb];
            if len == 1 && g.is_rule(a[p]) {
                return; // a lone reference
            }
            let w = prefix[p + len] - prefix[p];
            let ub = score((rb - lb + 1) as i64, w);
            if ub > min_saving {
                cands.push(Cand { ub, len, lb, rb });
            }
        };
        let mut st: Vec<(usize, usize)> = vec![(0, 0)]; // (lcp, lb)
        for i in 1..=n {
            let l = lcp.get(i).copied().unwrap_or(0);
            let mut lb = i - 1;
            while l < st.last().unwrap().0 {
                let (tl, tlb) = st.pop().unwrap();
                report(tl, tlb, i - 1);
                lb = tlb;
            }
            if l > st.last().unwrap().0 {
                st.push((l, lb));
            }
        }
        if cands.is_empty() {
            break;
        }
        cands.sort_unstable_by(|x, y| y.ub.cmp(&x.ub).then(y.len.cmp(&x.len)).then(x.lb.cmp(&y.lb)));
        let mut best = min_saving;
        let mut chosen: Option<(usize, Vec<usize>)> = None;
        for cd in &cands {
            if cd.ub <= best {
                break;
            }
            let mut pos = sa[cd.lb..=cd.rb].to_vec();
            pos.sort_unstable();
            let mut keep = Vec::new();
            let mut last = 0;
            for &p in &pos {
                if keep.is_empty() || p >= last {
                    keep.push(p);
                    last = p + cd.len;
                }
            }
            let w = prefix[pos[0] + cd.len] - prefix[pos[0]];
            let s = score(keep.len() as i64, w);
            if keep.len() >= 2 && s > best {
                best = s;
                chosen = Some((cd.len, keep));
            }
        }
        let Some((len, positions)) = chosen else { break };
        let word = a[positions[0]..positions[0] + len].to_vec();
        // replace, then split back at the separators
        let mut seqs: Vec<Vec<Sym>> = Vec::with_capacity(r_count + 1);
        let mut cur = Vec::new();
        let (mut i, mut q) = (0, 0);
        while i < n {
            let x = if q < positions.len() && positions[q] == i {
                i += len;
                q += 1;
                new_sym
            } else {
                i += 1;
                a[i - 1]
            };
            if x > new_sym {
                seqs.push(std::mem::take(&mut cur));
            } else {
                cur.push(x);
            }
        }
        let mut seqs = seqs.into_iter();
        g.main = seqs.next().unwrap();
        for r in g.rules.iter_mut() {
            *r = seqs.next().unwrap();
        }
        g.rules.push(word);
        added += 1;
    }
    added
}
