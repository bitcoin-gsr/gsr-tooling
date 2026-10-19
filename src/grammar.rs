//! A script as a grammar over instructions, and its exact committed size.
//!
//! Terminals are instructions (byte strings); symbol `t + k` is rule (macro) `k`. Rules may only use earlier
//! rules once ordered, which the declaration order chosen by [`evaluate`] guarantees.

use crate::opcodes::{OP_CALLMACRO, OP_MACRO};
use crate::order::choose_order;
use crate::script::{compact_len, write_compact, Decoded, Token};

pub type Sym = u32;

#[derive(Clone, Debug, Default)]
pub struct Grammar {
    /// Number of terminals: symbols below it are terminals, symbol `t + k` is rule `k`.
    pub t: usize,
    /// Byte length of each terminal.
    pub tcost: Vec<i64>,
    pub rules: Vec<Vec<Sym>>,
    pub main: Vec<Sym>,
}

/// Where the search starts: the script's own macros, or the fully unrolled script.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    Plain,
    Inline,
}

impl Grammar {
    pub fn is_rule(&self, x: Sym) -> bool {
        x as usize >= self.t
    }

    pub fn rule(&self, x: Sym) -> usize {
        x as usize - self.t
    }

    pub fn sym(&self, rule: usize) -> Sym {
        (self.t + rule) as Sym
    }
}

/// The script as a grammar -> (terminals, grammar). Terminal ids are canonical (sorted instructions, then the
/// protected ones in order, each a symbol of its own), so the result does not depend on the values of protected
/// instructions. Main-script instructions starting below `protect` are protected (only those of the main script
/// itself when starting inline).
pub fn from_script(d: &Decoded, start: Start, protect: usize) -> (Vec<Vec<u8>>, Grammar) {
    #[derive(Clone, Copy)]
    enum Raw<'a> {
        Term(&'a [u8]),
        Protected(&'a [u8]),
        Rule(usize),
    }
    let (rules_raw, main_raw): (Vec<Vec<Raw>>, Vec<Raw>) = match start {
        Start::Inline => {
            fn emit<'a>(
                d: &Decoded<'a>,
                toks: &[(Token<'a>, usize)],
                top: bool,
                protect: usize,
                out: &mut Vec<Raw<'a>>,
            ) {
                for &(t, p) in toks {
                    match t {
                        Token::Call(k) => emit(d, &d.bodies[k], false, protect, out),
                        Token::Op(b) if top && p < protect => out.push(Raw::Protected(b)),
                        Token::Op(b) => out.push(Raw::Term(b)),
                    }
                }
            }
            let mut seq = Vec::new();
            emit(d, &d.main, true, protect, &mut seq);
            (Vec::new(), seq)
        }
        Start::Plain => {
            fn conv(t: Token<'_>) -> Raw<'_> {
                match t {
                    Token::Call(k) => Raw::Rule(k),
                    Token::Op(b) => Raw::Term(b),
                }
            }
            let rules = d.bodies.iter().map(|b| b.iter().map(|&(t, _)| conv(t)).collect()).collect();
            let main = d
                .main
                .iter()
                .map(|&(t, p)| match t {
                    Token::Op(b) if p < protect => Raw::Protected(b),
                    _ => conv(t),
                })
                .collect();
            (rules, main)
        }
    };
    let mut plain: Vec<&[u8]> = rules_raw
        .iter()
        .chain(std::iter::once(&main_raw))
        .flatten()
        .filter_map(|x| match x {
            Raw::Term(b) => Some(*b),
            _ => None,
        })
        .collect();
    plain.sort_unstable();
    plain.dedup();
    let protected: Vec<&[u8]> = main_raw
        .iter()
        .filter_map(|x| match x {
            Raw::Protected(b) => Some(*b),
            _ => None,
        })
        .collect();
    let mut terms: Vec<Vec<u8>> = plain.iter().map(|b| b.to_vec()).collect();
    terms.extend(protected.iter().map(|b| b.to_vec()));
    let t = terms.len();
    let tid = |b: &[u8]| plain.binary_search(&b).unwrap() as Sym;
    let mut next_protected = plain.len();
    let mut ids = |s: &[Raw]| -> Vec<Sym> {
        s.iter()
            .map(|x| match *x {
                Raw::Term(b) => tid(b),
                Raw::Rule(k) => (t + k) as Sym,
                Raw::Protected(_) => {
                    next_protected += 1;
                    (next_protected - 1) as Sym
                }
            })
            .collect()
    };
    let rules = rules_raw.iter().map(|r| ids(r)).collect();
    let main = ids(&main_raw);
    let tcost = terms.iter().map(|b| b.len() as i64).collect();
    (terms, Grammar { t, tcost, rules, main })
}

/// Encodes a grammar whose rules are in declaration order -> (script, length of the declarations).
pub fn encode(terms: &[Vec<u8>], g: &Grammar) -> (Vec<u8>, usize) {
    let enc = |s: &[Sym], out: &mut Vec<u8>| {
        for &x in s {
            if g.is_rule(x) {
                out.push(OP_CALLMACRO.to_u8());
                write_compact(out, g.rule(x) as u64);
            } else {
                out.extend_from_slice(&terms[x as usize]);
            }
        }
    };
    let mut out = Vec::new();
    let mut body = Vec::new();
    for r in &g.rules {
        body.clear();
        enc(r, &mut body);
        out.push(OP_MACRO.to_u8());
        write_compact(&mut out, body.len() as u64);
        out.extend_from_slice(&body);
    }
    let decl_len = out.len();
    enc(&g.main, &mut out);
    (out, decl_len)
}

/// Exact committed size, the declaration order and the per-rule reference cost and uses.
pub struct Eval {
    pub total: i64,
    /// Declaration order (rule ids).
    pub order: Vec<usize>,
    /// Bytes of `OP_CALLMACRO` + index for each rule.
    pub refcost: Vec<i64>,
    /// Textual references to each rule.
    pub uses: Vec<i64>,
}

pub fn count_uses(g: &Grammar) -> Vec<i64> {
    let mut u = vec![0i64; g.rules.len()];
    for s in std::iter::once(&g.main).chain(&g.rules) {
        for &x in s {
            if g.is_rule(x) {
                u[g.rule(x)] += 1;
            }
        }
    }
    u
}

pub fn seq_bytes(g: &Grammar, s: &[Sym], refcost: &[i64]) -> i64 {
    s.iter().map(|&x| if g.is_rule(x) { refcost[g.rule(x)] } else { g.tcost[x as usize] }).sum()
}

pub fn evaluate(g: &Grammar) -> Eval {
    let uses = count_uses(g);
    let order = choose_order(g, &uses);
    let mut refcost = vec![0i64; g.rules.len()];
    for (i, &r) in order.iter().enumerate() {
        refcost[r] = 1 + compact_len(i as u64) as i64;
    }
    let mut total = seq_bytes(g, &g.main, &refcost);
    for r in &g.rules {
        let l = seq_bytes(g, r, &refcost);
        total += 1 + compact_len(l as u64) as i64 + l;
    }
    Eval { total, order, refcost, uses }
}

/// The grammar with its rules renumbered in declaration order.
pub fn in_declaration_order(g: &Grammar) -> Grammar {
    let e = evaluate(g);
    let mut pos = vec![0usize; g.rules.len()];
    for (i, &r) in e.order.iter().enumerate() {
        pos[r] = i;
    }
    let fix =
        |s: &[Sym]| -> Vec<Sym> { s.iter().map(|&x| if g.is_rule(x) { g.sym(pos[g.rule(x)]) } else { x }).collect() };
    Grammar {
        t: g.t,
        tcost: g.tcost.clone(),
        rules: e.order.iter().map(|&r| fix(&g.rules[r])).collect(),
        main: fix(&g.main),
    }
}

/// Drops the rules main does not reach, renumbering the rest.
pub fn drop_unreachable(g: &mut Grammar) {
    let n = g.rules.len();
    let mut seen = vec![false; n];
    let mut st = Vec::new();
    for &x in &g.main {
        if g.is_rule(x) && !seen[g.rule(x)] {
            seen[g.rule(x)] = true;
            st.push(g.rule(x));
        }
    }
    while let Some(r) = st.pop() {
        for &x in &g.rules[r] {
            if g.is_rule(x) && !seen[g.rule(x)] {
                seen[g.rule(x)] = true;
                st.push(g.rule(x));
            }
        }
    }
    let mut id = vec![usize::MAX; n];
    let mut kept = Vec::new();
    for (r, body) in std::mem::take(&mut g.rules).into_iter().enumerate() {
        if seen[r] {
            id[r] = kept.len();
            kept.push(body);
        }
    }
    let t = g.t;
    let fix = |s: &mut Vec<Sym>| {
        for x in s.iter_mut() {
            if *x as usize >= t {
                *x = (t + id[*x as usize - t]) as Sym;
            }
        }
    };
    for r in kept.iter_mut() {
        fix(r);
    }
    fix(&mut g.main);
    g.rules = kept;
}

/// Every rule's expansion into terminals.
pub fn expansions(g: &Grammar) -> Vec<Vec<Sym>> {
    let mut memo: Vec<Option<Vec<Sym>>> = vec![None; g.rules.len()];
    for r in 0..g.rules.len() {
        expand(g, r, &mut memo);
    }
    memo.into_iter().map(|m| m.unwrap()).collect()
}

fn expand(g: &Grammar, r: usize, memo: &mut Vec<Option<Vec<Sym>>>) {
    if memo[r].is_some() {
        return;
    }
    let mut e = Vec::new();
    for &x in &g.rules[r] {
        if g.is_rule(x) {
            expand(g, g.rule(x), memo);
            e.extend_from_slice(memo[g.rule(x)].as_ref().unwrap());
        } else {
            e.push(x);
        }
    }
    memo[r] = Some(e);
}

/// Main fully expanded into terminals.
pub fn unrolled(g: &Grammar) -> Vec<Sym> {
    let mut memo: Vec<Option<Vec<Sym>>> = vec![None; g.rules.len()];
    let mut u = Vec::new();
    for &x in &g.main {
        if g.is_rule(x) {
            expand(g, g.rule(x), &mut memo);
            u.extend_from_slice(memo[g.rule(x)].as_ref().unwrap());
        } else {
            u.push(x);
        }
    }
    u
}
