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

#[test]
fn anchor_rewrites_or_refuses() {
    let out = gsr(&["anchor", "--min-depth", "2"], b"52 79 77 77 77");
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "74519479777777");
    assert!(String::from_utf8(out.stderr).unwrap().contains("\"witness_items\": 3"));
    let out = gsr(&["anchor"], b"63 75 67 6d 68 51"); // two or three witness items
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr).unwrap().contains("different stack depths"));
}

#[test]
fn anchor_chooses_the_threshold() {
    let out = gsr(&["anchor"], b"52 79 77 77 77"); // no read 192 deep: not anchoring is smallest
    assert!(out.status.success());
    assert_eq!(String::from_utf8(out.stdout).unwrap().trim(), "5279777777");
    let summary = String::from_utf8(out.stderr).unwrap();
    for field in ["\"min_depth\": null", "\"compressed_bytes\": 5", "\"tried\": {\"none\": 5, \"512\": 5"] {
        assert!(summary.contains(field), "{summary}");
    }
    let out = gsr(&["anchor", "--min-depth", "2"], b"52 79 77 77 77");
    assert!(String::from_utf8(out.stderr).unwrap().contains("\"min_depth\": 2"));
    assert!(!gsr(&["anchor", "--min-depth", "deep"], b"51").status.success());
}

#[test]
fn analysis_commands() {
    let out = gsr(&["disasm"], b"d00151 d100 0105");
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "; 7 bytes = declarations (1, 3 bytes) + main script (4 bytes)\nmacro0 @0 (1 bytes)\n       2  1\nmain @3\n       3  call0\n       5  0x05\n"
    );
    let dir = std::env::temp_dir().join(format!("gsr-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let (plain, labels) = (dir.join("plain.hex"), dir.join("labels.txt"));
    std::fs::write(&plain, "5279777777").unwrap();
    std::fs::write(&labels, "# start end label\n0 2 the read\n2 5 nips\n").unwrap();
    let args = ["attribute", "--plain", plain.to_str().unwrap(), "--labels", labels.to_str().unwrap()];
    let out = gsr(&args, b"d003745194 d100 79777777");
    let text = String::from_utf8(out.stdout).unwrap();
    for field in ["\"bytes\": 11", "\"label\": \"the read\"", "\"main_bytes\": 3.0, \"declaration_bytes\": 5.0"] {
        assert!(text.contains(field), "{text}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
    let x = |n: u8| format!("01{n:02x} 79 939393939393");
    let script = format!("{} 76 {} 7c {} 7d {} 82", x(20), x(21), x(22), x(23));
    let out = gsr(&["near-duplicates", "--json"], script.as_bytes());
    let text = String::from_utf8(out.stdout).unwrap();
    for field in ["\"saving\": 6", "\"count\": 4", "\"step\": 1", "\"occurrences\": [0, 10, 20, 30]"] {
        assert!(text.contains(field), "{text}");
    }
}
