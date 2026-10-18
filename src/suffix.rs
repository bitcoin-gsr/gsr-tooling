//! Suffix and LCP arrays (prefix doubling with counting sort; Kasai).

pub fn suffix_array(s: &[u32]) -> Vec<usize> {
    let n = s.len();
    if n == 0 {
        return Vec::new();
    }
    let mut vals = s.to_vec();
    vals.sort_unstable();
    vals.dedup();
    let mut rk: Vec<usize> = s.iter().map(|x| vals.binary_search(x).unwrap()).collect();
    let mut sa: Vec<usize> = (0..n).collect();
    sa.sort_by_key(|&i| rk[i]);
    let mut tmp = vec![0usize; n];
    let mut cnt = Vec::new();
    let mut k = 1;
    loop {
        let mut p = 0;
        for i in n.saturating_sub(k)..n {
            tmp[p] = i;
            p += 1;
        }
        for &x in &sa {
            if x >= k {
                tmp[p] = x - k;
                p += 1;
            }
        }
        let m = rk.iter().copied().max().unwrap() + 1;
        cnt.clear();
        cnt.resize(m, 0usize);
        for &r in &rk {
            cnt[r] += 1;
        }
        for i in 1..m {
            cnt[i] += cnt[i - 1];
        }
        for &x in tmp.iter().rev() {
            cnt[rk[x]] -= 1;
            sa[cnt[rk[x]]] = x;
        }
        let sec = |i: usize| if i + k < n { rk[i + k] as i64 } else { -1 };
        tmp[sa[0]] = 0;
        for i in 1..n {
            let differs = rk[sa[i]] != rk[sa[i - 1]] || sec(sa[i]) != sec(sa[i - 1]);
            tmp[sa[i]] = tmp[sa[i - 1]] + differs as usize;
        }
        std::mem::swap(&mut rk, &mut tmp);
        if rk[sa[n - 1]] == n - 1 {
            break;
        }
        k <<= 1;
    }
    sa
}

/// `lcp[i]`: longest common prefix of the suffixes at `sa[i - 1]` and `sa[i]` (`lcp[0] = 0`).
pub fn lcp_array(s: &[u32], sa: &[usize]) -> Vec<usize> {
    let n = s.len();
    let mut rk = vec![0usize; n];
    for (i, &p) in sa.iter().enumerate() {
        rk[p] = i;
    }
    let mut lcp = vec![0usize; n];
    let mut h = 0;
    for i in 0..n {
        if rk[i] > 0 {
            let j = sa[rk[i] - 1];
            while i + h < n && j + h < n && s[i + h] == s[j + h] {
                h += 1;
            }
            lcp[rk[i]] = h;
            h = h.saturating_sub(1);
        } else {
            h = 0;
        }
    }
    lcp
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sorts_suffixes() {
        let s = [2, 1, 3, 1, 3, 1, 0];
        let sa = suffix_array(&s);
        let mut naive: Vec<usize> = (0..s.len()).collect();
        naive.sort_by(|&a, &b| s[a..].cmp(&s[b..]));
        assert_eq!(sa, naive);
        let lcp = lcp_array(&s, &sa);
        for i in 1..s.len() {
            let (a, b) = (&s[sa[i - 1]..], &s[sa[i]..]);
            assert_eq!(lcp[i], a.iter().zip(b).take_while(|(x, y)| x == y).count());
        }
    }
}
