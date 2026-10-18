//! Script encoding: reusable-macro declarations and references, CompactSize, instruction boundaries.

use crate::Error;

pub const OP_MACRO: u8 = 0xD0;
pub const OP_CALLMACRO: u8 = 0xD1;

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

/// The tokens of one body or of the main script, with their offsets in it.
fn tokens(code: &[u8], base: usize) -> Result<Vec<(Token<'_>, usize)>, Error> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < code.len() {
        let op = code[p];
        let (token, end) = match op {
            OP_CALLMACRO => {
                let (index, end) = read_compact(code, p + 1).map_err(|e| e.offset_by(base))?;
                (Token::Call(index as usize), end)
            }
            OP_MACRO => return Err(Error::MisplacedDeclaration(base + p)),
            _ => {
                let end = match op {
                    1..=75 => p + 1 + op as usize,
                    0x4C..=0x4E => {
                        let width = [1, 2, 4][(op - 0x4C) as usize];
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
    Ok(out)
}

/// A script split into its macro declarations and its main script, each tokenized. Well formed: declarations come
/// first, bodies reference only earlier declarations, and the main script only declared ones.
pub struct Decoded<'a> {
    pub bodies: Vec<Vec<(Token<'a>, usize)>>,
    pub main: Vec<(Token<'a>, usize)>,
    /// Offset of the main script: the length of the declarations.
    pub main_offset: usize,
}

pub fn decode(script: &[u8]) -> Result<Decoded<'_>, Error> {
    let mut bodies = Vec::new();
    let mut i = 0;
    while i < script.len() && script[i] == OP_MACRO {
        let (n, j) = read_compact(script, i + 1)?;
        let body = script.get(j..j + n as usize).ok_or(Error::Truncated(i))?;
        let toks = tokens(body, j)?;
        for &(t, p) in &toks {
            if let Token::Call(k) = t {
                if k >= bodies.len() {
                    return Err(Error::UndeclaredMacro { offset: j + p, index: k });
                }
            }
        }
        bodies.push(toks);
        i = j + n as usize;
    }
    let main = tokens(&script[i..], i)?;
    for &(t, p) in &main {
        if let Token::Call(k) = t {
            if k >= bodies.len() {
                return Err(Error::UndeclaredMacro { offset: i + p, index: k });
            }
        }
    }
    Ok(Decoded { bodies, main, main_offset: i })
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
        assert!(matches!(decode(&[OP_MACRO, 2, OP_CALLMACRO, 0, 0x51]), Err(Error::UndeclaredMacro { .. })));
        assert!(matches!(decode(&[0x05, 1, 2]), Err(Error::Truncated(0))));
        assert!(matches!(decode(&[0x51, OP_MACRO, 0]), Err(Error::MisplacedDeclaration(1))));
        let d = decode(&[OP_MACRO, 2, 0x51, 0x52, OP_CALLMACRO, 0, 0x93]).unwrap();
        assert_eq!(d.unroll(), vec![0x51, 0x52, 0x93]);
        assert_eq!(d.main_offset, 4);
    }
}
