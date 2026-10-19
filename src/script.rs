//! Script encoding: reusable-macro declarations and references, CompactSize, instruction boundaries.

use crate::opcodes::{Class, Opcode, OP_CALLMACRO, OP_MACRO};
use crate::Error;

const MACRO: u8 = OP_MACRO.to_u8();
const CALLMACRO: u8 = OP_CALLMACRO.to_u8();

/// Length of the canonical CompactSize encoding of `n`.
pub fn compact_len(n: u64) -> usize {
    match n {
        0..=252 => 1,
        253..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

/// Appends the canonical CompactSize encoding of `n`.
pub fn write_compact(out: &mut Vec<u8>, n: u64) {
    match compact_len(n) {
        1 => out.push(n as u8),
        3 => {
            out.push(0xFD);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        5 => {
            out.push(0xFE);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

/// Reads a canonical CompactSize at `i` -> (value, end).
fn read_compact(code: &[u8], i: usize) -> Result<(u64, usize), Error> {
    let prefix = *code.get(i).ok_or(Error::Truncated(i))?;
    let width = match prefix {
        0xFD => 2,
        0xFE => 4,
        0xFF => 8,
        _ => return Ok((prefix as u64, i + 1)),
    };
    let bytes = code.get(i + 1..i + 1 + width).ok_or(Error::Truncated(i))?;
    let mut le = [0u8; 8];
    le[..width].copy_from_slice(bytes);
    let n = u64::from_le_bytes(le);
    if compact_len(n) != 1 + width {
        return Err(Error::NonCanonicalCompactSize(i));
    }
    Ok((n, i + 1 + width))
}

/// An instruction: an opcode with its push data, or a reference to a declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Token<'a> {
    Op(&'a [u8]),
    Call(usize),
}

/// Appends the tokens of one body or of the main script to `out`, with their offsets in it, up to the first
/// instruction that does not decode. `base` is the offset of `code` in the script, `declared` the number of
/// declarations a reference may name.
fn tokens<'a>(code: &'a [u8], base: usize, declared: usize, out: &mut Vec<(Token<'a>, usize)>) -> Result<(), Error> {
    let mut p = 0;
    while p < code.len() {
        let op = code[p];
        let (token, end) = match Opcode::from_u8(op).class() {
            Class::Macro if op == CALLMACRO => {
                let (index, end) = read_compact(code, p + 1).map_err(|e| e.offset_by(base))?;
                if index >= declared as u64 {
                    return Err(Error::UndeclaredMacro { offset: base + p, index: index as usize });
                }
                (Token::Call(index as usize), end)
            }
            Class::Macro => return Err(Error::MisplacedDeclaration(base + p)),
            class => {
                let end = match class {
                    Class::PushBytes(n) => p + 1 + n as usize,
                    Class::PushData(width) => {
                        let width = width as usize;
                        let mut le = [0u8; 4];
                        le[..width].copy_from_slice(code.get(p + 1..p + 1 + width).ok_or(Error::Truncated(base + p))?);
                        p + 1 + width + u32::from_le_bytes(le) as usize
                    }
                    _ => p + 1,
                };
                (Token::Op(code.get(p..end).ok_or(Error::Truncated(base + p))?), end)
            }
        };
        out.push((token, p));
        p = end;
    }
    Ok(())
}

/// A script split into its macro declarations and its main script, each tokenized. Well formed: declarations come
/// first, bodies reference only earlier declarations, and the main script only declared ones.
pub struct Decoded<'a> {
    pub bodies: Vec<Vec<(Token<'a>, usize)>>,
    pub main: Vec<(Token<'a>, usize)>,
    /// Offset of the main script: the length of the declarations.
    pub main_offset: usize,
    pub declarations: Vec<Span>,
}

/// Where a declaration is: its `OP_MACRO` at `at`, its body from `body` to `end`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub at: usize,
    pub body: usize,
    pub end: usize,
}

pub fn decode(script: &[u8]) -> Result<Decoded<'_>, Error> {
    match decode_prefix(script) {
        (d, None) => Ok(d),
        (_, Some(e)) => Err(e),
    }
}

/// Decodes as consensus does, in serialized order, up to the first failure -> (what decoded before it, the
/// failure). A body cut short by the failure keeps its tokens before it.
pub fn decode_prefix(script: &[u8]) -> (Decoded<'_>, Option<Error>) {
    let mut d = Decoded { bodies: Vec::new(), main: Vec::new(), main_offset: 0, declarations: Vec::new() };
    let mut i = 0;
    while i < script.len() && script[i] == MACRO {
        let (n, j) = match read_compact(script, i + 1) {
            Ok(x) => x,
            Err(e) => return (d, Some(e)),
        };
        let Some(body) = script.get(j..).filter(|rest| rest.len() as u64 >= n).map(|rest| &rest[..n as usize]) else {
            return (d, Some(Error::Truncated(i)));
        };
        let mut toks = Vec::new();
        let decoded = tokens(body, j, d.bodies.len(), &mut toks);
        d.bodies.push(toks);
        d.declarations.push(Span { at: i, body: j, end: j + body.len() });
        if let Err(e) = decoded {
            return (d, Some(e));
        }
        i = j + body.len();
    }
    d.main_offset = i;
    let decoded = tokens(&script[i..], i, d.bodies.len(), &mut d.main);
    (d, decoded.err())
}

impl Decoded<'_> {
    /// The script the interpreter runs: every reference replaced by its body, recursively.
    pub fn unroll(&self) -> Vec<u8> {
        fn emit(d: &Decoded, toks: &[(Token, usize)], out: &mut Vec<u8>) {
            for &(t, _) in toks {
                match t {
                    Token::Op(bytes) => out.extend_from_slice(bytes),
                    Token::Call(k) => emit(d, &d.bodies[k], out),
                }
            }
        }
        let mut out = Vec::new();
        emit(self, &self.main, &mut out);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_round_trip() {
        for n in [0, 252, 253, 0xFFFF, 0x1_0000, 0xFFFF_FFFF, 0x1_0000_0000] {
            let mut b = Vec::new();
            write_compact(&mut b, n);
            assert_eq!(b.len(), compact_len(n));
            assert_eq!(read_compact(&b, 0).unwrap(), (n, b.len()));
        }
        assert_eq!(read_compact(&[0xFD, 0x10, 0x00], 0), Err(Error::NonCanonicalCompactSize(0)));
    }

    #[test]
    fn rejects_malformed_scripts() {
        // a reference to a later declaration, a truncated push, OP_MACRO after the declarations
        assert!(matches!(decode(&[MACRO, 2, CALLMACRO, 0, 0x51]), Err(Error::UndeclaredMacro { .. })));
        assert!(matches!(decode(&[0x05, 1, 2]), Err(Error::Truncated(0))));
        assert!(matches!(decode(&[0x51, MACRO, 0]), Err(Error::MisplacedDeclaration(1))));
        let d = decode(&[MACRO, 2, 0x51, 0x52, CALLMACRO, 0, 0x93]).unwrap();
        assert_eq!(d.unroll(), vec![0x51, 0x52, 0x93]);
        assert_eq!(d.main_offset, 4);
    }
}
