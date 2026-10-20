//! A readable listing of a script: its declarations, then its main script, one instruction per line with its byte
//! offset in the script.
//!
//! Opcodes are named without `OP_`; references are `call<k>`; minimal pushes of numbers of up to 8 bytes are the
//! number in decimal (`OP_0`–`OP_16` included), other pushes of up to 8 bytes their data in hex (`0x0500`), longer
//! ones their length (`<32B>`) or, with `data`, their data in hex.

use std::fmt::Write;

use crate::opcodes::Opcode;
use crate::script::{decode, minimal_push, number, push_data, Token};
use crate::Error;

/// The listing of `script`; with `data`, long pushes show their data.
pub fn disasm(script: &[u8], data: bool) -> Result<String, Error> {
    let d = decode(script)?;
    let mut out = String::new();
    let main_len = script.len() - d.main_offset;
    let _ = writeln!(
        out,
        "; {} bytes = declarations ({}, {} bytes) + main script ({main_len} bytes)",
        script.len(),
        d.bodies.len(),
        d.main_offset
    );
    for (k, body) in d.bodies.iter().enumerate() {
        let span = d.declarations[k];
        let _ = writeln!(out, "macro{k} @{} ({} bytes)", span.at, span.end - span.body);
        for &(t, p) in body {
            let _ = writeln!(out, "{:>8}  {}", span.body + p, token_text(t, data));
        }
    }
    let _ = writeln!(out, "main @{}", d.main_offset);
    for &(t, p) in &d.main {
        let _ = writeln!(out, "{:>8}  {}", d.main_offset + p, token_text(t, data));
    }
    Ok(out)
}

fn token_text(t: Token, data: bool) -> String {
    match t {
        Token::Op(bytes) => instruction_text(bytes, data),
        Token::Call(k) => format!("call{k}"),
    }
}

/// One instruction as [`disasm`] lists it.
pub fn instruction_text(instruction: &[u8], data: bool) -> String {
    let op = Opcode::from_u8(instruction[0]);
    let name = op.name();
    let pushed = push_data(instruction);
    match (number(instruction), pushed) {
        (Some(n), _) if minimal_push(n) == instruction => n.to_string(),
        (_, Some(d)) if d.len() <= 8 || data => format!("0x{}", hex(d)),
        (_, Some(d)) => format!("<{}B>", d.len()),
        _ => name.strip_prefix("OP_").unwrap_or(name).to_string(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(2 * bytes.len()), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}
