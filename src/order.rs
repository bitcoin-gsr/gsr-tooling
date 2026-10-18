//! Declaration order: which rules get one-byte indices.
//!
//! The hot set is a dependency-closed set of at most [`HOT`] rules with the most references (each hot reference
//! is 2 bytes shorter). The Lagrangian relaxation max Σ(uses − λ) over closed sets is solved by a minimum cut for
//! the smallest λ whose closure fits; the remaining slots are filled greedily. The plain greedy fill is the
//! fallback; the better of the two is kept. Then a topological order with the hot set first.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};

use crate::grammar::Grammar;

/// Indices below this encode in one CompactSize byte.
pub const HOT: usize = 253;

/// Maximum flow (Dinic) for the closure problem.
struct Flow {
    to: Vec<usize>,
    cap: Vec<i64>,
    adj: Vec<Vec<usize>>,
    level: Vec<i64>,
    it: Vec<usize>,
}

impl Flow {
    fn new(n: usize) -> Self {
        Flow { to: Vec::new(), cap: Vec::new(), adj: vec![Vec::new(); n], level: vec![0; n], it: vec![0; n] }
    }

    fn add(&mut self, a: usize, b: usize, c: i64) {
        self.adj[a].push(self.to.len());
        self.to.push(b);
        self.cap.push(c);
        self.adj[b].push(self.to.len());
        self.to.push(a);
        self.cap.push(0);
    }

    fn bfs(&mut self, s: usize, t: usize) -> bool {
        self.level.fill(-1);
        let mut q = VecDeque::from([s]);
        self.level[s] = 0;
        while let Some(v) = q.pop_front() {
            for &id in &self.adj[v] {
                let u = self.to[id];
                if self.cap[id] > 0 && self.level[u] < 0 {
                    self.level[u] = self.level[v] + 1;
                    q.push_back(u);
                }
            }
        }
        self.level[t] >= 0
    }

    fn dfs(&mut self, v: usize, t: usize, f: i64) -> i64 {
        if v == t {
            return f;
        }
        while self.it[v] < self.adj[v].len() {
            let id = self.adj[v][self.it[v]];
            let u = self.to[id];
            if self.cap[id] > 0 && self.level[u] == self.level[v] + 1 {
                let d = self.dfs(u, t, f.min(self.cap[id]));
                if d > 0 {
                    self.cap[id] -= d;
                    self.cap[id ^ 1] += d;
                    return d;
                }
            }
            self.it[v] += 1;
        }
        0
    }

    fn run(&mut self, s: usize, t: usize) {
        while self.bfs(s, t) {
            self.it.fill(0);
            while self.dfs(s, t, i64::MAX / 4) > 0 {}
        }
    }
}

/// The smallest dependency-closed set maximizing Σ(uses − λ): the source side of a minimum cut.
fn closure(deps: &[Vec<usize>], uses: &[i64], lambda: i64) -> Vec<bool> {
    let n = deps.len();
    let (s, t) = (n, n + 1);
    let mut f = Flow::new(n + 2);
    for v in 0..n {
        let p = uses[v] - lambda;
        if p > 0 {
            f.add(s, v, p);
        }
        if p < 0 {
            f.add(v, t, -p);
        }
        for &d in &deps[v] {
            f.add(v, d, i64::MAX / 8);
        }
    }
    f.run(s, t);
    f.bfs(s, t); // reachable in the residual graph
    (0..n).map(|v| f.level[v] >= 0).collect()
}

/// Adds rules by references, each with its missing dependencies, while they fit.
fn fill_hot(deps: &[Vec<usize>], uses: &[i64], hot: &mut [bool]) {
    let n = deps.len();
    let mut nhot = hot.iter().filter(|&&h| h).count();
    let mut byuse: Vec<usize> = (0..n).collect();
    byuse.sort_by_key(|&r| Reverse(uses[r])); // stable: ties by index
    let mut stamp = vec![usize::MAX; n];
    let mut stack = Vec::new();
    for &r in &byuse {
        if nhot >= HOT {
            break;
        }
        if hot[r] {
            continue;
        }
        let mut miss = Vec::new();
        stack.clear();
        stack.push(r);
        stamp[r] = r;
        while let Some(v) = stack.pop() {
            miss.push(v);
            for &d in &deps[v] {
                if !hot[d] && stamp[d] != r {
                    stamp[d] = r;
                    stack.push(d);
                }
            }
        }
        if nhot + miss.len() > HOT {
            continue;
        }
        for &v in &miss {
            hot[v] = true;
        }
        nhot += miss.len();
    }
}

pub fn choose_order(g: &Grammar, uses: &[i64]) -> Vec<usize> {
    let n = g.rules.len();
    let deps: Vec<Vec<usize>> = g
        .rules
        .iter()
        .map(|r| {
            let mut d: Vec<usize> = r.iter().filter(|&&x| g.is_rule(x)).map(|&x| g.rule(x)).collect();
            d.sort_unstable();
            d.dedup();
            d
        })
        .collect();
    let mut hot = vec![false; n];
    fill_hot(&deps, uses, &mut hot);
    if n > HOT {
        let value = |h: &[bool]| -> i64 { (0..n).filter(|&v| h[v]).map(|v| uses[v]).sum() };
        let (mut lo, mut hi) = (0i64, uses.iter().copied().max().unwrap() + 1); // closure(hi) is empty
        while lo < hi {
            let mid = (lo + hi) / 2;
            if closure(&deps, uses, mid).iter().filter(|&&c| c).count() <= HOT {
                hi = mid;
            } else {
                lo = mid + 1;
            }
        }
        let mut lag = closure(&deps, uses, lo);
        fill_hot(&deps, uses, &mut lag);
        if value(&lag) > value(&hot) {
            hot = lag;
        }
    }
    // Kahn's algorithm: hot rules before cold ones, busiest first among ready rules
    let mut indeg = vec![0usize; n];
    let mut users = vec![Vec::new(); n];
    for (r, d) in deps.iter().enumerate() {
        for &x in d {
            indeg[r] += 1;
            users[x].push(r);
        }
    }
    let key = |r: usize| Reverse((!hot[r], Reverse(uses[r]), r));
    let mut pq: BinaryHeap<_> = (0..n).filter(|&r| indeg[r] == 0).map(key).collect();
    let mut order = Vec::with_capacity(n);
    while let Some(Reverse((_, _, r))) = pq.pop() {
        order.push(r);
        for &v in &users[r] {
            indeg[v] -= 1;
            if indeg[v] == 0 {
                pq.push(key(v));
            }
        }
    }
    assert_eq!(order.len(), n, "cycle in grammar");
    order
}
