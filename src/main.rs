//! `gsr`: tools for Tapleaf 0xC2 (GSR) scripts. Scripts are read and written as hex.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use gsr::{check, compress, info, lower_bounds, unroll, Report, Severity, Start};

#[derive(Parser)]
#[command(name = "gsr", version, about = "Tools for Tapleaf 0xC2 (GSR) scripts; scripts are hex")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Check a script without executing it: consensus errors, policy warnings and lints
    ///
    /// Exits with 1 if there are errors, or warnings or lints with --deny.
    Check {
        /// Input file (default: stdin)
        input: Option<PathBuf>,
        /// Print the report as JSON
        #[arg(long)]
        json: bool,
        /// Also fail on warnings, or on warnings and lints
        #[arg(long, value_name = "LEVEL")]
        deny: Option<Deny>,
    },
    /// Shrink a script with reusable macros (it unrolls to exactly the same script)
    ///
    /// Writes the compressed script, and a JSON summary to stderr.
    Compress {
        /// Input file (default: stdin)
        input: Option<PathBuf>,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Keep the main script's first N bytes literal at their offsets
        #[arg(long, value_name = "N", default_value_t = 0)]
        protect: usize,
    },
    /// Write the script a macro-compressed script runs
    Unroll {
        /// Input file (default: stdin)
        input: Option<PathBuf>,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Print the script's sizes and unrolling charge as JSON
    Info {
        /// Input file (default: stdin)
        input: Option<PathBuf>,
        /// Also compute lower bounds on any macro encoding
        #[arg(long)]
        bounds: bool,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum Deny {
    Warnings,
    Lints,
}

fn read_script(input: &Option<PathBuf>) -> Result<Vec<u8>, String> {
    let text = match input {
        Some(path) if path.as_os_str() != "-" => {
            std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?
        }
        _ => {
            let mut s = String::new();
            std::io::stdin().read_to_string(&mut s).map_err(|e| format!("stdin: {e}"))?;
            s
        }
    };
    let hex: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if hex.len() % 2 != 0 {
        return Err("odd number of hex digits".into());
    }
    let digit = |c: u8| (c as char).to_digit(16).ok_or_else(|| format!("not a hex digit: {:?}", c as char));
    hex.chunks(2).map(|p| Ok((digit(p[0])? * 16 + digit(p[1])?) as u8)).collect()
}

fn write_script(output: &Option<PathBuf>, script: &[u8]) -> Result<(), String> {
    let mut text = String::with_capacity(2 * script.len() + 1);
    for b in script {
        text.push_str(&format!("{b:02x}"));
    }
    text.push('\n');
    match output {
        Some(path) if path.as_os_str() != "-" => {
            std::fs::write(path, text).map_err(|e| format!("{}: {e}", path.display()))
        }
        _ => std::io::stdout().write_all(text.as_bytes()).map_err(|e| format!("stdout: {e}")),
    }
}

/// A flat JSON object from (key, already-encoded value) pairs.
fn json(fields: &[(&str, String)]) -> String {
    let body: Vec<String> = fields.iter().map(|(k, v)| format!("\"{k}\": {v}")).collect();
    format!("{{{}}}", body.join(", "))
}

fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn json_opt(v: Option<usize>) -> String {
    v.map_or("null".into(), |v| v.to_string())
}

fn report_json(r: &Report) -> String {
    let diagnostics: Vec<String> = r
        .diagnostics
        .iter()
        .map(|d| {
            json(&[
                ("severity", json_str(d.severity().id())),
                ("rule", json_str(d.rule.id())),
                ("offset", d.offset.to_string()),
                ("macro", json_opt(d.declaration)),
                ("message", json_str(&d.message)),
            ])
        })
        .collect();
    let witness_items = r
        .witness_items
        .as_ref()
        .map_or("null".into(), |w| format!("[{}]", w.iter().map(|n| n.to_string()).collect::<Vec<_>>().join(", ")));
    let stopped = r.stack_analysis_stopped.as_ref().map_or("null".into(), |s| {
        json(&[("offset", s.offset.to_string()), ("macro", json_opt(s.declaration)), ("reason", json_str(&s.reason))])
    });
    json(&[
        ("decoding", json_str(r.decoding.id())),
        ("errors", r.count(Severity::Error).to_string()),
        ("warnings", r.count(Severity::Warning).to_string()),
        ("lints", r.count(Severity::Lint).to_string()),
        ("witness_items", witness_items),
        ("stack_analysis_stopped", stopped),
        ("diagnostics", format!("[{}]", diagnostics.join(", "))),
    ])
}

fn report_text(r: &Report) -> String {
    let mut out = String::new();
    for d in &r.diagnostics {
        out.push_str(&format!("{d}\n"));
    }
    if let Some(s) = &r.stack_analysis_stopped {
        let at = s.declaration.map_or(String::new(), |k| format!(" (macro {k})"));
        out.push_str(&format!("note: the stack analysis stopped at byte {}{at}: {}\n", s.offset, s.reason));
    }
    let plural = |n: usize, word: &str| format!("{n} {word}{}", if n == 1 { "" } else { "s" });
    let witness = match &r.witness_items {
        Some(w) => {
            let w: Vec<String> = w.iter().map(|n| n.to_string()).collect();
            format!("; witness items: {}", w.join(" or "))
        }
        None => String::new(),
    };
    out.push_str(&format!(
        "{}{witness}; {}, {}, {}\n",
        r.decoding.id(),
        plural(r.count(Severity::Error), "error"),
        plural(r.count(Severity::Warning), "warning"),
        plural(r.count(Severity::Lint), "lint"),
    ));
    out
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Check { input, json, deny } => {
            let r = check(&read_script(&input)?);
            print!("{}", if json { report_json(&r) + "\n" } else { report_text(&r) });
            let failed = r.count(Severity::Error) > 0
                || deny >= Some(Deny::Warnings) && r.count(Severity::Warning) > 0
                || deny >= Some(Deny::Lints) && r.count(Severity::Lint) > 0;
            return Ok(if failed { ExitCode::FAILURE } else { ExitCode::SUCCESS });
        }
        Command::Compress { input, output, protect } => {
            let script = read_script(&input)?;
            let t0 = Instant::now();
            let (out, st) = compress(&script, protect).map_err(|e| e.to_string())?;
            let charge = info(&out).map_err(|e| e.to_string())?.unrolling_charge;
            write_script(&output, &out)?;
            let start = match st.start {
                Start::Plain => "\"plain\"",
                Start::Inline => "\"inline\"",
            };
            eprintln!(
                "{}",
                json(&[
                    ("input_bytes", st.input_bytes.to_string()),
                    ("output_bytes", st.output_bytes.to_string()),
                    ("declarations", st.declarations.to_string()),
                    ("decl_len", st.decl_len.to_string()),
                    ("unrolling_charge", charge.to_string()),
                    ("start", start.to_string()),
                    ("min_saving", st.min_saving.to_string()),
                    ("seconds", format!("{:.1}", t0.elapsed().as_secs_f64())),
                ])
            );
        }
        Command::Unroll { input, output } => {
            let script = read_script(&input)?;
            write_script(&output, &unroll(&script).map_err(|e| e.to_string())?)?;
        }
        Command::Info { input, bounds } => {
            let script = read_script(&input)?;
            let i = info(&script).map_err(|e| e.to_string())?;
            let mut fields = vec![
                ("bytes", i.bytes.to_string()),
                ("declarations", i.declarations.to_string()),
                ("decl_len", i.decl_len.to_string()),
                ("unrolled_bytes", i.unrolled_bytes.to_string()),
                ("substituted", i.substituted.to_string()),
                ("references", i.references.to_string()),
                ("unrolling_charge", i.unrolling_charge.to_string()),
            ];
            if bounds {
                let b = lower_bounds(&script).map_err(|e| e.to_string())?;
                fields.push(("distinct_instruction_bytes", b.distinct_instruction_bytes.to_string()));
                fields.push(("lz_bound", b.lz.to_string()));
            }
            println!("{}", json(&fields));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("gsr: {e}");
            ExitCode::FAILURE
        }
    }
}
