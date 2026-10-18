//! Minimal grammar parsing and local search.
//!
//! Every rule body and the main script are re-parsed optimally (dynamic programming over the unrolled
//! instructions, with the current rules' expansions as the dictionary and their exact reference costs); rules that
//! do not pay for themselves are removed; repeat until the size stops falling.

use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::{BuildHasherDefault, Hasher};

use crate::grammar::{drop_unreachable, evaluate, expansions, seq_bytes, unrolled, Grammar, Sym};
use crate::script::compact_len;

/// FxHash: the automaton's child maps are hot and their keys are small integers.
#[derive(Default, Clone, Copy)]
struct Fx(u64);

impl Hasher for Fx {
    fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.write_u64(b as u64);
        }
    }
    fn write_u32(&mut self, i: u32) {
        self.write_u64(i as u64);
    }
    fn write_u64(&mut self, i: u64) {
        self.0 = (self.0.rotate_left(5) ^ i).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

type FxMap<K, V> = HashMap<K, V, BuildHasherDefault<Fx>>;

const NONE: usize = usize::MAX;

/// Aho–Corasick automaton over the rules' expansions.
struct Automaton {
    next: Vec<FxMap<Sym, usize>>,
    fail: Vec<usize>,
    /// The word (rule) ending at a node, or NONE.
    word: Vec<usize>,
    /// The next word-end node in the fail chain, or NONE.
    out: Vec<usize>,
}

impl Automaton {
    fn new(words: &[Vec<Sym>]) -> Self {
        let mut ac = Automaton { next: Vec::new(), fail: Vec::new(), word: Vec::new(), out: Vec::new() };
        ac.add_node();
        for (id, w) in words.iter().enumerate() {
            let mut v = 0;
            for &x in w {
                v = match ac.next[v].get(&x) {
                    Some(&u) => u,
                    None => {
                        let u = ac.add_node();
                        ac.next[v].insert(x, u);
                        u
                    }
                };
            }
            ac.word[v] = id; // a later duplicate wins
        }
        // breadth first: fail links point to shallower nodes, so the visiting order within a level is irrelevant
        let mut q: VecDeque<usize> = ac.next[0].values().copied().collect();
        while let Some(v) = q.pop_front() {
            let children: Vec<(Sym, usize)> = ac.next[v].iter().map(|(&x, &u)| (x, u)).collect();
            for (x, u) in children {
                let mut f = ac.fail[v];
                while f != 0 && !ac.next[f].contains_key(&x) {
                    f = ac.fail[f];
                }
                ac.fail[u] = match ac.next[f].get(&x) {
                    Some(&w) if w != u => w,
                    _ => 0,
                };
                let fu = ac.fail[u];
                ac.out[u] = if ac.word[fu] != NONE { fu } else { ac.out[fu] };
                q.push_back(u);
            }
        }
        ac
    }

    fn add_node(&mut self) -> usize {
        self.next.push(FxMap::default());
        self.fail.push(0);
        self.word.push(NONE);
        self.out.push(NONE);
        self.next.len() - 1
    }

    fn step(&self, mut v: usize, x: Sym) -> usize {
        loop {
            if let Some(&u) = self.next[v].get(&x) {
                return u;
            }
            if v == 0 {
                return 0;
            }
            v = self.fail[v];
        }
    }
}

/// Optimal parse of `text` (terminals) with the words, excluding words of length >= `maxlen` and the word
/// `skip`. Minimizes bytes, then references.
fn parse(
    g: &Grammar,
    ac: &Automaton,
    words: &[Vec<Sym>],
    wcost: &[i64],
    text: &[Sym],
    maxlen: usize,
    skip: usize,
) -> Vec<Sym> {
    let m = text.len();
    let mut dp = vec![i64::MAX / 4; m + 1];
    let mut refs = vec![0u32; m + 1];
    let mut from = vec![0usize; m + 1];
    let mut how = vec![0 as Sym; m + 1];
    dp[0] = 0;
    let mut v = 0;
    for j in 1..=m {
        let t = text[j - 1];
        dp[j] = dp[j - 1] + g.tcost[t as usize];
        refs[j] = refs[j - 1];
        from[j] = j - 1;
        how[j] = t;
        v = ac.step(v, t);
        let mut u = if ac.word[v] != NONE { v } else { ac.out[v] };
        while u != NONE && u != 0 {
            let w = ac.word[u];
            let l = words[w].len();
            if l < maxlen && w != skip {
                let c = dp[j - l] + wcost[w];
                let rf = refs[j - l] + 1;
                if c < dp[j] || (c == dp[j] && rf < refs[j]) {
                    dp[j] = c;
                    refs[j] = rf;
                    from[j] = j - l;
                    how[j] = g.sym(w);
                }
            }
            u = ac.out[u];
        }
    }
    let mut out = Vec::new();
    let mut j = m;
    while j > 0 {
        out.push(how[j]);
        j = from[j];
    }
    out.reverse();
    out
}

/// Every rule body re-parsed with the other rules, and main parsed from `u` (main unrolled).
fn reparse(g: &Grammar, words: &[Vec<Sym>], wcost: &[i64], u: &[Sym], keep: Option<usize>) -> Grammar {
    let ac = Automaton::new(words);
    let rules =
        (0..g.rules.len())
            .map(|r| {
                if Some(r) == keep {
                    words[r].clone()
                } else {
                    parse(g, &ac, words, wcost, &words[r], words[r].len(), r)
                }
            })
            .collect();
    let main = parse(g, &ac, words, wcost, u, usize::MAX, NONE);
    let mut h = Grammar { t: g.t, tcost: g.tcost.clone(), rules, main };
    drop_unreachable(&mut h); // a word shadowed by a duplicate has a one-reference body: its rule becomes unused
    h
}

/// Re-parses with the current rules and removes rules that do not pay, for at most `rounds` rounds or until the
/// size stops falling; returns the smallest grammar seen.
pub fn mgp(g0: &Grammar, rounds: usize) -> Grammar {
    let mut best = g0.clone();
    let mut best_total = evaluate(&best).total;
    let mut g = g0.clone();
    let u = unrolled(&g);
    for _ in 0..rounds {
        drop_unreachable(&mut g);
        let e = evaluate(&g);
        let words = expansions(&g);
        let h = reparse(&g, &words, &e.refcost, &u, None);
        let eh = evaluate(&h);
        if eh.total < best_total {
            best_total = eh.total;
            best = h.clone();
        }
        // remove rules that do not pay, uses * (body - reference) <= body + header: at most the worst fifth per
        // round, since removing a rule lengthens the bodies that used it and makes them pay more
        let n = h.rules.len();
        let mut bad: Vec<(i64, usize)> = (0..n)
            .filter_map(|r| {
                let l = seq_bytes(&h, &h.rules[r], &eh.refcost);
                let d = eh.uses[r] * (l - eh.refcost[r]) - (l + 1 + compact_len(l as u64) as i64);
                (d <= 0).then_some((d, r))
            })
            .collect();
        bad.sort_unstable();
        let nk = bad.len().min((n / 5).max(1));
        if nk == 0 && eh.total >= e.total {
            break;
        }
        let mut kill = vec![false; n];
        for &(_, r) in &bad[..nk] {
            kill[r] = true;
        }
        g = inline_killed(&h, &kill);
        if nk == 0 {
            break;
        }
    }
    best
}

/// The grammar with the killed rules inlined into their users (the next parse may replace them with other words).
fn inline_killed(h: &Grammar, kill: &[bool]) -> Grammar {
    fn body(h: &Grammar, kill: &[bool], r: usize, memo: &mut Vec<Option<Vec<Sym>>>) {
        if memo[r].is_some() {
            return;
        }
        let mut o = Vec::new();
        for &x in &h.rules[r] {
            if h.is_rule(x) && kill[h.rule(x)] {
                body(h, kill, h.rule(x), memo);
                o.extend_from_slice(memo[h.rule(x)].as_ref().unwrap());
            } else {
                o.push(x);
            }
        }
        memo[r] = Some(o);
    }
    let n = h.rules.len();
    let mut memo = vec![None; n];
    let mut id = vec![usize::MAX; n];
    let mut rules = Vec::new();
    for r in 0..n {
        if !kill[r] {
            body(h, kill, r, &mut memo);
            id[r] = rules.len();
            rules.push(memo[r].clone().unwrap());
        }
    }
    let mut main = Vec::new();
    for &x in &h.main {
        if h.is_rule(x) && kill[h.rule(x)] {
            body(h, kill, h.rule(x), &mut memo);
            main.extend_from_slice(memo[h.rule(x)].as_ref().unwrap());
        } else {
            main.push(x);
        }
    }
    let mut k = Grammar { t: h.t, tcost: h.tcost.clone(), rules, main };
    let t = k.t;
    let fix = |s: &mut Vec<Sym>| {
        for x in s.iter_mut() {
            if *x as usize >= t {
                *x = (t + id[*x as usize - t]) as Sym;
            }
        }
    };
    for r in k.rules.iter_mut() {
        fix(r);
    }
    fix(&mut k.main);
    k
}

/// Local search over the set of words: drops one rule (its occurrences are re-parsed optimally with the other
/// words) and keeps the change if the exact size falls. Rules are tried least profitable first.
pub fn local_search(mut g: Grammar, sweeps: usize) -> Grammar {
    let u = unrolled(&g);
    let mut cur = evaluate(&g).total;
    for _ in 0..sweeps {
        let mut tried: HashSet<Vec<Sym>> = HashSet::new();
        let mut improved = false;
        loop {
            drop_unreachable(&mut g);
            let e = evaluate(&g);
            let words = expansions(&g);
            let mut cand: Vec<(i64, usize)> = (0..g.rules.len())
                .filter(|&r| !tried.contains(&words[r]))
                .map(|r| {
                    let l = seq_bytes(&g, &g.rules[r], &e.refcost);
                    (e.uses[r] * (l - e.refcost[r]) - (l + 1 + compact_len(l as u64) as i64), r)
                })
                .collect();
            if cand.is_empty() {
                break;
            }
            cand.sort_unstable();
            let ac = Automaton::new(&words);
            let mut accepted = false;
            for &(_, r) in &cand {
                tried.insert(words[r].clone());
                let mut wcost = e.refcost.clone();
                wcost[r] = 1 << 20; // banned
                let rules = (0..g.rules.len())
                    .map(|q| {
                        if q == r {
                            words[r].clone()
                        } else {
                            parse(&g, &ac, &words, &wcost, &words[q], words[q].len(), q)
                        }
                    })
                    .collect();
                let main = parse(&g, &ac, &words, &wcost, &u, usize::MAX, NONE);
                let mut h = Grammar { t: g.t, tcost: g.tcost.clone(), rules, main };
                drop_unreachable(&mut h);
                let t = evaluate(&h).total;
                if t < cur {
                    cur = t;
                    g = h;
                    accepted = true;
                    improved = true;
                    break;
                }
            }
            if !accepted {
                break;
            }
        }
        // re-optimize the parse with the new costs
        let h = mgp(&g, 10);
        let t = evaluate(&h).total;
        if t < cur {
            cur = t;
            g = h;
            improved = true;
        }
        if !improved {
            break;
        }
    }
    g
}
