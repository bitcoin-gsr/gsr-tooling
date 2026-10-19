//! The `gsr` command line.

use std::io::Write;
use std::process::{Command, Output, Stdio};

fn gsr(args: &[&str], stdin: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_gsr"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

fn data(name: &str) -> String {
    std::fs::read_to_string(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

#[test]
fn compress_and_unroll() {
    let input = data("sample2.hex");
    let out = gsr(&["compress"], input.as_bytes());
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout.clone()).unwrap(), data("sample2.out.hex"));
    let summary = String::from_utf8(out.stderr).unwrap();
    assert!(summary.contains("\"output_bytes\": 1706"), "{summary}");
    let unrolled = gsr(&["unroll", "-"], &out.stdout);
    assert_eq!(String::from_utf8(unrolled.stdout).unwrap(), input); // sample2 has no macros of its own
}

#[test]
fn info_prints_json() {
    let out = gsr(&["info", "--bounds"], data("sample2.out.hex").as_bytes());
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    for field in ["\"bytes\": 1706", "\"unrolling_charge\": 543968", "\"lz_bound\": 1176"] {
        assert!(text.contains(field), "{text}");
    }
}

#[test]
fn rejects_bad_input() {
    let out = gsr(&["info"], b"0g");
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr).unwrap().contains("not a hex digit"));
    let out = gsr(&["info"], b"d1 00"); // a reference without declarations
    assert!(String::from_utf8(out.stderr).unwrap().contains("undeclared macro"));
}

#[test]
fn check_reports_and_exits() {
    let out = gsr(&["check"], data("sample2.out.hex").as_bytes());
    assert_eq!(out.status.code(), Some(1)); // a fragment: it leaves 600 items on the stack
    assert!(String::from_utf8(out.stdout).unwrap().contains("error[stack-unsatisfiable]"));
    let out = gsr(&["check", "--json"], b"0105 75 51"); // a non-minimal push
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    for field in
        ["\"decoding\": \"well-formed\"", "\"warnings\": 1", "\"rule\": \"non-minimal-push\"", "\"witness_items\": [0]"]
    {
        assert!(text.contains(field), "{text}");
    }
    assert_eq!(gsr(&["check", "--deny", "warnings"], b"0105 75 51").status.code(), Some(1));
    assert_eq!(gsr(&["check", "--deny", "lints"], b"d00193 d100").status.code(), Some(1)); // a single-use macro
    assert_eq!(gsr(&["check", "--deny", "warnings"], b"d00193 d100").status.code(), Some(0));
}
