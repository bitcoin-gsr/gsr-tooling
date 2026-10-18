//! `gsr`: tools for Tapleaf 0xC2 (GSR) scripts. Scripts are read and written as hex.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand};
use gsr_tooling::{info, lower_bounds, optimize, unroll, Start};

#[derive(Parser)]
#[command(name = "gsr", version, about = "Tools for Tapleaf 0xC2 (GSR) scripts; scripts are hex")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
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

fn run(cli: Cli) -> Result<(), String> {
    match cli.command {
        Command::Compress { input, output, protect } => {
            let script = read_script(&input)?;
            let t0 = Instant::now();
            let (out, st) = optimize(&script, protect).map_err(|e| e.to_string())?;
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
    Ok(())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gsr: {e}");
            ExitCode::FAILURE
        }
    }
}
