//! A lower bound on the committed size of any grammar for a script.
//!
//! The cheapest LZ77-style parse where an instruction costs its bytes and a copy of any earlier substring (overlap
//! allowed) costs 2 bytes, the cheapest reference. A grammar maps to such a parse by expanding the first occurrence
//! of each rule and copying the later ones, at no more than its symbol cost; headers are ignored, so the bound is
//! loose.

use crate::grammar::{unrolled, Grammar};
use crate::suffix::{lcp_array, suffix_array};

pub fn lz_bound(g: &Grammar) -> i64 {
    let u = unrolled(g);
    let n = u.len();
    let sa = suffix_array(&u);
    let lcp = lcp_array(&u, &sa);
    // longest previous factor: the nearest lexicographic neighbour on each side that starts earlier has the
    // longest common prefix
    let mut lpf = vec![0usize; n];
    for i in 0..n {
        let p = sa[i];
        let mut m = usize::MAX;
        for j in (0..i).rev() {
            m = m.min(lcp[j + 1]);
            if m <= lpf[p] {
                break;
            }
            if sa[j] < p {
                lpf[p] = lpf[p].max(m);
                break;
            }
        }
        m = usize::MAX;
        for j in i + 1..n {
            m = m.min(lcp[j]);
            if m <= lpf[p] {
                break;
            }
            if sa[j] < p {
                lpf[p] = lpf[p].max(m);
                break;
            }
        }
    }
    let mut dp = vec![i64::MAX / 4; n + 1];
    dp[0] = 0;
    let mut ptr = 0; // smallest i with i + lpf[i] >= j
    for j in 1..=n {
        dp[j] = dp[j - 1] + g.tcost[u[j - 1] as usize];
        while ptr < j && ptr + lpf[ptr] < j {
            ptr += 1;
        }
        if ptr < j {
            dp[j] = dp[j].min(dp[ptr] + 2);
        }
    }
    dp[n]
}
