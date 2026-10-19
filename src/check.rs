//! Static checks of a Tapleaf 0xC2 script, without executing it: consensus errors, policy warnings and lints.
//!
//! The consensus rules are those of jmoik/bitcoin `gsr` @ `ad6c16f`: `reusable_macros::Decode` (the first
//! OP_SUCCESSx or decoding failure in serialized order decides), `Unroll` (at most 4,000,000 unrolled bytes) and
//! `EvalTapleaf0xC2` with `CheckTapleaf0xC2ScriptResult` (failing opcodes, conditionals, exactly one item left on
//! the stack). The policy rules are the minimal pushes and the upgradable NOPs of the standard script flags.
//!
//! The stack analysis follows every path through the conditionals with the stack depths relative to the witness
//! (no values): it finds the witness item counts that end with exactly one item, and paths that cannot get past an
//! instruction. It stops at instructions whose stack effect depends on values it does not track (`OP_PICK` and
//! `OP_ROLL` without a literal depth, `OP_TX`). Branch conditions are not tracked either, so a path may combine
//! branches that no witness takes together; errors are only reported when no path at all gets through.

use std::collections::HashSet;
use std::fmt;

use crate::opcodes::{Class, Opcode};
use crate::script::{compact_len, decode_prefix, Decoded, Span, Token};
use crate::Error;

/// The most bytes a script may unroll to.
const MAX_UNROLLED_SIZE: u64 = 4_000_000;
/// The most items the stack and altstack may hold together, and so the most witness items.
const MAX_STACK_SIZE: i64 = 32_768;
/// The most distinct stack states the analysis follows at one point.
const MAX_PATHS: usize = 256;

/// How much a finding matters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Consensus: the leaf can never be spent, or anyone can spend it.
    Error,
    /// Policy: spends are not relayed.
    Warning,
    /// Wasted bytes or varops.
    Lint,
}

impl Severity {
    pub fn id(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Lint => "lint",
        }
    }
}

/// What a finding is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Rule {
    /// An OP_SUCCESSx decodes before any decoding failure: the leaf succeeds unconditionally.
    OpSuccess,
    /// A decoding failure before any OP_SUCCESSx.
    Malformed,
    /// The script unrolls to more than 4,000,000 bytes.
    UnrolledSize,
    /// No path gets past this instruction: `OP_VERIF` or `OP_VERNOTIF` anywhere, or `OP_RETURN`,
    /// `OP_CHECKMULTISIG(VERIFY)` or `OP_INVALIDOPCODE` on every remaining path.
    AlwaysFails,
    /// `OP_ELSE` or `OP_ENDIF` without `OP_IF`, or `OP_IF` without `OP_ENDIF`.
    UnbalancedConditional,
    /// `OP_FROMALTSTACK` with an empty altstack on every remaining path.
    AltstackUnderflow,
    /// No number of witness items gets through the script with exactly one item left on the stack.
    StackUnsatisfiable,
    /// A push that is not the shortest encoding of its data.
    NonMinimalPush,
    /// `OP_NOP1` or `OP_NOP4`–`OP_NOP10`, kept for upgrades.
    UpgradableNop,
    /// A declaration the main script never reaches.
    UnusedMacro,
    /// A declaration referenced once: inlining it is shorter.
    SingleUseMacro,
}

impl Rule {
    pub fn id(self) -> &'static str {
        match self {
            Rule::OpSuccess => "op-success",
            Rule::Malformed => "malformed",
            Rule::UnrolledSize => "unrolled-size",
            Rule::AlwaysFails => "always-fails",
            Rule::UnbalancedConditional => "unbalanced-conditional",
            Rule::AltstackUnderflow => "altstack-underflow",
            Rule::StackUnsatisfiable => "stack-unsatisfiable",
            Rule::NonMinimalPush => "non-minimal-push",
            Rule::UpgradableNop => "upgradable-nop",
            Rule::UnusedMacro => "unused-macro",
            Rule::SingleUseMacro => "single-use-macro",
        }
    }

    pub fn severity(self) -> Severity {
        match self {
            Rule::NonMinimalPush | Rule::UpgradableNop => Severity::Warning,
            Rule::UnusedMacro | Rule::SingleUseMacro => Severity::Lint,
            _ => Severity::Error,
        }
    }
}

/// The outcome of consensus decoding, which runs before execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Decoding {
    WellFormed,
    /// The leaf succeeds unconditionally: anyone can spend it.
    OpSuccess,
    /// The leaf can never be spent.
    Malformed,
}

impl Decoding {
    pub fn id(self) -> &'static str {
        match self {
            Decoding::WellFormed => "well-formed",
            Decoding::OpSuccess => "op-success",
            Decoding::Malformed => "malformed",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Diagnostic {
    pub rule: Rule,
    /// Offset in the committed script of the instruction or declaration.
    pub offset: usize,
    /// The declaration whose body holds the instruction.
    pub declaration: Option<usize>,
    pub message: String,
}

impl Diagnostic {
    pub fn severity(&self) -> Severity {
        self.rule.severity()
    }
}

impl fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}] byte {}", self.severity().id(), self.rule.id(), self.offset)?;
        if let Some(k) = self.declaration {
            write!(f, " (macro {k})")?;
        }
        write!(f, ": {}", self.message)
    }
}

/// Where and why the stack analysis stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stop {
    pub offset: usize,
    pub declaration: Option<usize>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Report {
    pub decoding: Decoding,
    /// Errors first, then warnings and lints, each by offset.
    pub diagnostics: Vec<Diagnostic>,
    /// The witness item counts with which some path ends with exactly one item on the stack, when the stack
    /// analysis ran to the end.
    pub witness_items: Option<Vec<u64>>,
    /// Set when the stack analysis could not run to the end.
    pub stack_analysis_stopped: Option<Stop>,
}

impl Report {
    pub fn count(&self, severity: Severity) -> usize {
        self.diagnostics.iter().filter(|d| d.severity() == severity).count()
    }
}

/// Checks a script without executing it.
pub fn check(script: &[u8]) -> Report {
    let mut report = Report {
        decoding: Decoding::WellFormed,
        diagnostics: Vec::new(),
        witness_items: None,
        stack_analysis_stopped: None,
    };
    run(script, &mut report);
    report.diagnostics.sort_by_key(|d| (d.severity(), d.offset));
    report
}

fn run(script: &[u8], report: &mut Report) {
    let (d, failure) = decode_prefix(script);
    // Everything decode_prefix returns precedes the failure, in serialized order: bodies, then the main script.
    let sequences = d.bodies.iter().enumerate().map(|(k, b)| (b, d.declarations[k].body, Some(k)));
    for (toks, base, declaration) in sequences.chain(std::iter::once((&d.main, d.main_offset, None))) {
        for &(t, p) in toks {
            let Token::Op(bytes) = t else { continue };
            let op = Opcode::from_u8(bytes[0]);
            if !op.is_op_success() {
                continue;
            }
            let message = if report.decoding == Decoding::OpSuccess {
                format!("{op} is another OP_SUCCESSx")
            } else {
                format!(
                    "{op} is an OP_SUCCESSx in Tapleaf 0xC2: the leaf succeeds unconditionally, so anyone can spend it"
                )
            };
            report.decoding = Decoding::OpSuccess;
            report.diagnostics.push(Diagnostic { rule: Rule::OpSuccess, offset: base + p, declaration, message });
        }
    }
    if let Some(e) = failure {
        let message = if report.decoding == Decoding::OpSuccess {
            format!("{e}, after the OP_SUCCESSx that decides")
        } else {
            report.decoding = Decoding::Malformed;
            format!("{e}: the leaf can never be spent")
        };
        report.diagnostics.push(Diagnostic {
            rule: Rule::Malformed,
            offset: e.offset(),
            declaration: d.declarations.iter().position(|s| s.at <= e.offset() && e.offset() < s.end),
            message,
        });
    }
    if report.decoding != Decoding::WellFormed {
        return;
    }

    macro_lints(&d, &mut report.diagnostics);
    let unrolled = crate::info(script).expect("decoded above").unrolled_bytes;
    if unrolled > MAX_UNROLLED_SIZE {
        report.diagnostics.push(Diagnostic {
            rule: Rule::UnrolledSize,
            offset: d.main_offset,
            declaration: None,
            message: format!(
                "unrolls to {unrolled} bytes, over the limit of {MAX_UNROLLED_SIZE}: the leaf can never be spent"
            ),
        });
        return;
    }

    let mut walk = Walk::new();
    // the unrolled script: every reference replaced by its body
    let mut stack = vec![(&d.main[..], d.main_offset, None)];
    while let Some(top) = stack.last_mut() {
        let Some((&(t, p), rest)) = top.0.split_first() else {
            stack.pop();
            continue;
        };
        let (base, declaration) = (top.1, top.2);
        top.0 = rest;
        match t {
            Token::Call(k) => stack.push((&d.bodies[k][..], d.declarations[k].body, Some(k))),
            Token::Op(bytes) => walk.step(bytes, Loc { offset: base + p, declaration }),
        }
    }
    walk.finish(script.len(), report);
}

/// Unused and single-use declarations.
fn macro_lints(d: &Decoded, out: &mut Vec<Diagnostic>) {
    let n = d.bodies.len();
    let mut reached = vec![false; n];
    let mut uses = vec![0usize; n];
    let mut todo = vec![&d.main];
    while let Some(toks) = todo.pop() {
        for &(t, _) in toks {
            if let Token::Call(k) = t {
                uses[k] += 1;
                if !reached[k] {
                    reached[k] = true;
                    todo.push(&d.bodies[k]);
                }
            }
        }
    }
    for (k, &Span { at, body, end }) in d.declarations.iter().enumerate() {
        let message = if !reached[k] {
            format!("the main script never reaches it: removing it saves {} bytes", end - at)
        } else if uses[k] == 1 {
            let saved = body - at + 1 + compact_len(k as u64);
            format!("referenced once: inlining it saves {saved} bytes")
        } else {
            continue;
        };
        let rule = if reached[k] { Rule::SingleUseMacro } else { Rule::UnusedMacro };
        out.push(Diagnostic { rule, offset: at, declaration: Some(k), message });
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Loc {
    offset: usize,
    declaration: Option<usize>,
}

/// The stack on one path, relative to the witness: `delta` items more than the witness has, `alt` items on the
/// altstack; the path needs at least `need` witness items, first at `need_at`.
#[derive(Clone, Copy, Debug)]
struct State {
    delta: i64,
    alt: i64,
    need: i64,
    need_at: Loc,
}

/// The paths through one conditional: those executing the current branch, and those waiting for the other.
struct Frame {
    active: Vec<State>,
    waiting: Vec<State>,
}

struct Walk {
    diagnostics: Vec<Diagnostic>,
    seen: HashSet<(Rule, usize)>,
    /// Open `OP_IF`/`OP_NOTIF`s, for balance.
    open: Vec<Loc>,
    /// The conditionals the stack analysis is inside, outermost first; empty once it stopped.
    frames: Vec<Frame>,
    stopped: Option<Stop>,
    /// The number the previous instruction pushed, if it was a push of at most 8 bytes.
    literal: Option<u64>,
}

impl Walk {
    fn new() -> Self {
        let start = State { delta: 0, alt: 0, need: 0, need_at: Loc { offset: 0, declaration: None } };
        Walk {
            diagnostics: Vec::new(),
            seen: HashSet::new(),
            open: Vec::new(),
            frames: vec![Frame { active: vec![start], waiting: Vec::new() }],
            stopped: None,
            literal: None,
        }
    }

    fn report(&mut self, rule: Rule, at: Loc, message: impl FnOnce() -> String) {
        if self.seen.insert((rule, at.offset)) {
            self.diagnostics.push(Diagnostic {
                rule,
                offset: at.offset,
                declaration: at.declaration,
                message: message(),
            });
        }
    }

    fn stop(&mut self, at: Loc, reason: String) {
        if self.stopped.is_none() {
            self.stopped = Some(Stop { offset: at.offset, declaration: at.declaration, reason });
            self.frames.clear();
        }
    }

    /// Whether some path is still running; true once the analysis stopped, as it then cannot tell.
    fn live(&self) -> bool {
        self.stopped.is_some() || self.frames.iter().any(|f| !f.active.is_empty() || !f.waiting.is_empty())
    }

    fn step(&mut self, bytes: &[u8], at: Loc) {
        let op = Opcode::from_u8(bytes[0]);
        let literal = self.literal.take();
        match op.class() {
            Class::PushBytes(_) | Class::PushData(_) => {
                let data = &bytes[bytes.len() - push_len(bytes)..];
                if let Some(expected) = non_minimal(bytes[0], data) {
                    self.report(Rule::NonMinimalPush, at, || {
                        format!("{}-byte push with {op}: policy requires {expected}", data.len())
                    });
                }
                self.apply(at, 0, 1, 0, 0);
                if data.len() <= 8 {
                    self.literal = Some(data.iter().rev().fold(0, |n, &b| n << 8 | b as u64));
                }
            }
            Class::PushNum(n) => {
                self.apply(at, 0, 1, 0, 0);
                self.literal = Some(n as u64);
            }
            Class::UpgradableNop => {
                self.report(Rule::UpgradableNop, at, || {
                    format!("{op} is kept for upgrades: policy rejects it when executed")
                });
            }
            Class::FailsWhenReached => {
                // runs even in a branch that is not executed
                if self.live() {
                    self.report(Rule::AlwaysFails, at, || {
                        format!("{op} fails when reached, even in a branch that is not taken")
                    });
                }
                for f in &mut self.frames {
                    f.active.clear();
                    f.waiting.clear();
                }
            }
            Class::FailsWhenExecuted => {
                let was_live = self.live();
                if let Some(f) = self.frames.last_mut() {
                    f.active.clear();
                }
                // without the analysis, outside conditionals: every path executes it
                let unconditional = self.stopped.is_some() && self.open.is_empty();
                if was_live && !self.live() || unconditional {
                    self.report(Rule::AlwaysFails, at, || {
                        format!("{op} fails when executed, and every remaining path executes it")
                    });
                }
            }
            Class::Conditional => self.conditional(op, at),
            // decoding fails or succeeds before execution on these
            Class::OpSuccess | Class::Macro => unreachable!("{op} in a well-formed unrolled script"),
            Class::Operation => match op.stack_effect() {
                Some(e) => self.apply(at, e.pop.into(), e.push.into(), e.alt_pop.into(), e.alt_push.into()),
                None => match (op.to_u8(), literal) {
                    // OP_PICK and OP_ROLL with a literal depth n: n + 1 items below n, then n + 1 (OP_ROLL) or n + 2
                    (0x79 | 0x7a, Some(n)) if n < MAX_STACK_SIZE as u64 => {
                        let n = n as i64;
                        self.apply(at, n + 2, if op.to_u8() == 0x79 { n + 2 } else { n + 1 }, 0, 0);
                    }
                    (0x79 | 0x7a, Some(n)) => self.stop(at, format!("{op} with depth {n}, beyond the stack limit")),
                    (0x79 | 0x7a, None) => self.stop(at, format!("{op} with a depth computed at run time")),
                    // OP_IFDUP: (x -- x) if x is zero, else (x -- x x)
                    (0x73, _) => {
                        if let Some(f) = self.frames.last_mut() {
                            let copies = f.active.clone();
                            f.active.extend(copies);
                            let half = f.active.len() / 2;
                            for (i, s) in f.active.iter_mut().enumerate() {
                                raise_need(s, 1, at);
                                s.delta += if i < half { 0 } else { 1 };
                            }
                            normalize(&mut f.active);
                        }
                        self.check_paths(at);
                    }
                    _ => self.stop(at, format!("{op}'s stack effect depends on its operands")),
                },
            },
        }
    }

    fn conditional(&mut self, op: Opcode, at: Loc) {
        match op.to_u8() {
            // OP_IF, OP_NOTIF
            0x63 | 0x64 => {
                self.open.push(at);
                self.apply(at, 1, 0, 0, 0);
                if let Some(f) = self.frames.last_mut() {
                    let active = std::mem::take(&mut f.active);
                    self.frames.push(Frame { waiting: active.clone(), active });
                }
            }
            // OP_ELSE, OP_ENDIF
            byte => {
                if self.open.is_empty() {
                    self.report(Rule::UnbalancedConditional, at, || format!("{op} without OP_IF"));
                    self.stop(at, format!("{op} without OP_IF"));
                    return;
                }
                if byte == 0x67 {
                    if let Some(f) = self.frames.last_mut() {
                        std::mem::swap(&mut f.active, &mut f.waiting);
                    }
                    return;
                }
                self.open.pop();
                if let Some(f) = self.frames.pop() {
                    let parent = self.frames.last_mut().expect("a frame per open conditional");
                    parent.active.extend(f.active);
                    parent.active.extend(f.waiting);
                    normalize(&mut parent.active);
                    self.check_paths(at);
                }
            }
        }
    }

    /// Applies a stack effect to the paths executing here.
    fn apply(&mut self, at: Loc, pop: i64, push: i64, alt_pop: i64, alt_push: i64) {
        let was_live = self.live();
        let Some(f) = self.frames.last_mut() else { return };
        f.active.retain_mut(|s| {
            raise_need(s, pop, at);
            s.delta += push - pop;
            s.alt += alt_push - alt_pop;
            s.alt >= 0
        });
        if f.active.len() > 1 {
            normalize(&mut f.active);
        }
        if was_live && !self.live() {
            self.report(Rule::AltstackUnderflow, at, || "the altstack is empty on every remaining path".into());
        }
        self.check_paths(at);
    }

    fn check_paths(&mut self, at: Loc) {
        if self.frames.last().is_some_and(|f| f.active.len() > MAX_PATHS) {
            self.stop(at, format!("more than {MAX_PATHS} distinct stack depths"));
        }
    }

    fn finish(mut self, end: usize, report: &mut Report) {
        for at in std::mem::take(&mut self.open) {
            self.report(Rule::UnbalancedConditional, at, || "OP_IF or OP_NOTIF without OP_ENDIF".into());
            self.stop(at, "unbalanced conditional".into());
        }
        if self.stopped.is_none() {
            let states = &self.frames[0].active;
            let mut items: Vec<u64> = states
                .iter()
                .filter(|s| {
                    let w = 1 - s.delta;
                    w >= s.need.max(0) && w <= MAX_STACK_SIZE
                })
                .map(|s| (1 - s.delta) as u64)
                .collect();
            items.sort_unstable();
            items.dedup();
            if items.is_empty() {
                if let Some(s) = states.first() {
                    let w = 1 - s.delta;
                    let (at, message) = if w < 0 {
                        let message = format!(
                            "even an empty witness leaves {} items on the stack; exactly one must remain",
                            s.delta
                        );
                        (Loc { offset: end, declaration: None }, message)
                    } else if w > MAX_STACK_SIZE {
                        let message = format!("ending with one item on the stack takes {w} witness items, over the limit of {MAX_STACK_SIZE}");
                        (Loc { offset: end, declaration: None }, message)
                    } else {
                        let message = format!(
                            "needs at least {} witness items here, but ending with exactly one item on the stack takes {w}",
                            s.need
                        );
                        (s.need_at, message)
                    };
                    self.report(Rule::StackUnsatisfiable, at, || message);
                }
            } else {
                report.witness_items = Some(items);
            }
        }
        report.diagnostics.extend(self.diagnostics);
        report.stack_analysis_stopped = self.stopped;
    }
}

fn raise_need(s: &mut State, pop: i64, at: Loc) {
    if pop - s.delta > s.need {
        s.need = pop - s.delta;
        s.need_at = at;
    }
}

/// Keeps one state per (delta, alt): the one needing the fewest witness items.
fn normalize(states: &mut Vec<State>) {
    states.sort_by_key(|s| (s.delta, s.alt, s.need));
    states.dedup_by_key(|s| (s.delta, s.alt));
}

/// Length of a push instruction's data.
fn push_len(bytes: &[u8]) -> usize {
    match Opcode::from_u8(bytes[0]).class() {
        Class::PushBytes(n) => n as usize,
        Class::PushData(width) => bytes.len() - 1 - width as usize,
        _ => 0,
    }
}

/// The encoding policy requires for a push of `data` with `op`, if `op` is not it (Bitcoin Core's
/// `CheckMinimalPush`, but `OP_1NEGATE` is an OP_SUCCESSx in Tapleaf 0xC2, so 0x81 takes a direct push).
fn non_minimal(op: u8, data: &[u8]) -> Option<&'static str> {
    const NUMS: [&str; 17] = [
        "OP_0", "OP_1", "OP_2", "OP_3", "OP_4", "OP_5", "OP_6", "OP_7", "OP_8", "OP_9", "OP_10", "OP_11", "OP_12",
        "OP_13", "OP_14", "OP_15", "OP_16",
    ];
    let (ok, expected) = match data {
        [] => (op == 0x00, "OP_0"),
        &[n @ 1..=16] => (false, NUMS[n as usize]),
        _ if data.len() <= 75 => (op as usize == data.len(), "a direct push"),
        _ if data.len() <= 255 => (op == 0x4c, "OP_PUSHDATA1"),
        _ if data.len() <= 65535 => (op == 0x4d, "OP_PUSHDATA2"),
        _ => (true, ""),
    };
    (!ok).then_some(expected)
}

impl Error {
    /// Offset of the failure in the script.
    pub fn offset(&self) -> usize {
        match *self {
            Error::Truncated(o) | Error::NonCanonicalCompactSize(o) | Error::MisplacedDeclaration(o) => o,
            Error::UndeclaredMacro { offset, .. } => offset,
        }
    }
}
