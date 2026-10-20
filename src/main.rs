//! `gsr`: tools for Tapleaf 0xC2 (GSR) scripts. Scripts are read and written as hex.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use clap::{Parser, Subcommand, ValueEnum};
use gsr::{
    anchor, anchor_auto, attribute, check, compress, disasm, info, lower_bounds, near_duplicates, unroll, Attribution,
    LabelledRange, NearDuplicate, Report, Severity, Start,
};

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
    /// Address deep stack reads from the bottom, so they repeat and compress
    ///
    /// Rewrites `<d> OP_PICK|OP_ROLL` in the main script, d at least --min-depth, to `OP_DEPTH <H-d> OP_SUB
    /// OP_PICK|OP_ROLL`, where the stack height H is fixed by the only witness item count that can succeed. Refuses
    /// when it cannot prove that. The proof covers the stack depths only: the rewritten script costs more varops,
    /// holds a few more stack bytes, and changes what depends on the script's bytes or length (see docs). Writes the
    /// script, and a JSON summary to stderr.
    Anchor {
        /// Input file (default: stdin)
        input: Option<PathBuf>,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Rewrite reads at least N deep, or with `auto` choose N (or no anchoring) by compressing with each of
        /// 192, 224, 256, 288, 320, 384 and 512 and keeping the smallest (about a minute for a 150 kB script)
        #[arg(long, value_name = "N|auto", default_value = "auto", value_parser = parse_min_depth)]
        min_depth: MinDepth,
        /// Leave the main script's first N bytes as they are
        #[arg(long, value_name = "N", default_value_t = 0)]
        protect: usize,
    },
    /// List a script readably: declarations and main script, one instruction per line with its byte offset
    ///
    /// References are call<k>; minimal number pushes of up to 8 bytes are decimal, other short pushes 0x<hex>,
    /// longer ones <nB>.
    Disasm {
        /// Input file (default: stdin)
        input: Option<PathBuf>,
        /// Output file (default: stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
        /// Show the data of long pushes in hex
        #[arg(long)]
        data: bool,
    },
    /// Attribute a compressed script's bytes to labelled byte ranges of the plain script it was made from
    ///
    /// The compressed script must unroll to the plain script, or to it anchored by `gsr anchor`. Prints JSON: per
    /// label, its share of the main script and of the declarations it uses (split by unrolled bytes), and the
    /// declarations only it uses.
    Attribute {
        /// The compressed script (default: stdin)
        input: Option<PathBuf>,
        /// The plain script, before anchoring and compression
        #[arg(long, value_name = "FILE")]
        plain: PathBuf,
        /// Labelled ranges of the plain script's bytes, one per line: `start end label` (end exclusive); the
        /// shortest range containing an offset labels it
        #[arg(long, value_name = "FILE")]
        labels: PathBuf,
    },
    /// Report instruction sequences that repeat except for a few pushed numbers, by estimated saving
    ///
    /// Searches the declarations and main script as committed; numbers are pushes of up to 8 bytes. The saving is
    /// that of one macro for all occurrences if the numbers agreed, less what macros for the parts between them
    /// save already: a ranking, not a prediction.
    NearDuplicates {
        /// Input file (default: stdin)
        input: Option<PathBuf>,
        /// How many to report
        #[arg(long, value_name = "N", default_value_t = 20)]
        top: usize,
        /// The most numbers that may differ between occurrences
        #[arg(long, value_name = "N", default_value_t = 2)]
        max_varying: usize,
        /// Print JSON, with every occurrence's offset
        #[arg(long)]
        json: bool,
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

#[derive(Clone, Copy)]
enum MinDepth {
    Auto,
    Fixed(u64),
}

fn parse_min_depth(s: &str) -> Result<MinDepth, String> {
    if s == "auto" {
        return Ok(MinDepth::Auto);
    }
    s.parse().map(MinDepth::Fixed).map_err(|_| format!("expected a number or `auto`, not `{s}`"))
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
    write_text(output, &text)
}

fn write_text(output: &Option<PathBuf>, text: &str) -> Result<(), String> {
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

/// `start end label` lines; blank lines and lines starting with `#` are skipped.
fn read_ranges(path: &PathBuf) -> Result<Vec<LabelledRange>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut ranges = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(3, char::is_whitespace);
        let bad = || format!("{}:{}: expected `start end label`", path.display(), i + 1);
        let mut num = || parts.next().and_then(|p| p.parse::<usize>().ok()).ok_or_else(bad);
        let (start, end) = (num()?, num()?);
        let label = parts.next().map(str::trim).filter(|l| !l.is_empty()).ok_or_else(bad)?;
        ranges.push(LabelledRange { start, end, label: label.to_string() });
    }
    Ok(ranges)
}

fn attribution_json(a: &Attribution) -> String {
    let labels: Vec<String> = a
        .labels
        .iter()
        .map(|l| {
            json(&[
                ("label", l.label.as_deref().map_or("null".into(), json_str)),
                ("plain_bytes", l.plain_bytes.to_string()),
                ("unrolled_bytes", l.unrolled_bytes.to_string()),
                ("main_bytes", format!("{:.1}", l.main_bytes)),
                ("declaration_bytes", format!("{:.1}", l.declaration_bytes)),
                ("bytes", format!("{:.1}", l.main_bytes + l.declaration_bytes)),
                ("declarations", l.declarations.to_string()),
                ("exclusive_declaration_bytes", l.exclusive_declaration_bytes.to_string()),
            ])
        })
        .collect();
    json(&[
        ("bytes", a.bytes.to_string()),
        ("main_bytes", a.main_bytes.to_string()),
        ("declaration_bytes", a.declaration_bytes.to_string()),
        ("labels", format!("[\n  {}\n]", labels.join(",\n  "))),
    ])
}

fn near_json(n: &NearDuplicate) -> String {
    let pattern: Vec<String> = n.pattern.iter().map(|t| json_str(t)).collect();
    let offsets: Vec<String> = n.occurrences.iter().map(|o| o.to_string()).collect();
    let varying: Vec<String> = n
        .varying
        .iter()
        .map(|v| {
            json(&[
                ("index", v.index.to_string()),
                ("min", v.min.to_string()),
                ("max", v.max.to_string()),
                ("distinct", v.distinct.to_string()),
                ("step", v.step.map_or("null".into(), |s| s.to_string())),
                ("before", v.before.as_deref().map_or("null".into(), json_str)),
            ])
        })
        .collect();
    json(&[
        ("saving", n.saving.to_string()),
        ("count", n.occurrences.len().to_string()),
        ("bytes", n.bytes.to_string()),
        ("total_bytes", n.total_bytes.to_string()),
        ("pattern", format!("[{}]", pattern.join(", "))),
        ("varying", format!("[{}]", varying.join(", "))),
        ("occurrences", format!("[{}]", offsets.join(", "))),
    ])
}

fn near_text(found: &[NearDuplicate]) -> String {
    let mut out = String::new();
    for (i, n) in found.iter().enumerate() {
        out.push_str(&format!(
            "{:>3}. ~{} B  {}x {} B  {}\n",
            i + 1,
            n.saving,
            n.occurrences.len(),
            n.bytes,
            n.pattern.join(" ")
        ));
        for (j, v) in n.varying.iter().enumerate() {
            let step = v.step.map_or(String::new(), |s| format!(", step {s:+}"));
            let before = v.before.as_deref().map_or(String::new(), |b| format!(", before {b}"));
            out.push_str(&format!("       ${}: {}..{} ({} distinct{step}{before})\n", j + 1, v.min, v.max, v.distinct));
        }
        let shown: Vec<String> = n.occurrences.iter().take(5).map(|o| o.to_string()).collect();
        let more = if n.occurrences.len() > 5 { ", ..." } else { "" };
        out.push_str(&format!("       at {}{more}\n", shown.join(", ")));
    }
    out
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
        Command::Anchor { input, output, min_depth, protect } => {
            let script = read_script(&input)?;
            let t0 = Instant::now();
            let (out, st, tried) = match min_depth {
                MinDepth::Fixed(n) => {
                    let (out, st) = anchor(&script, n, protect)?;
                    (out, st, Vec::new())
                }
                MinDepth::Auto => anchor_auto(&script, protect)?,
            };
            write_script(&output, &out)?;
            let mut fields = vec![
                ("input_bytes", st.input_bytes.to_string()),
                ("output_bytes", st.output_bytes.to_string()),
                ("rewritten", st.rewritten.to_string()),
                ("kept", st.kept.to_string()),
                ("witness_items", st.witness_items.to_string()),
                ("min_depth", json_opt(st.min_depth.map(|n| n as usize))),
            ];
            if !tried.is_empty() {
                let best = tried.iter().map(|t| t.1).min().unwrap_or(0);
                let sizes: Vec<(String, String)> =
                    tried.iter().map(|&(t, n)| (t.map_or("none".into(), |t| t.to_string()), n.to_string())).collect();
                let sizes: Vec<(&str, String)> = sizes.iter().map(|(k, v)| (k.as_str(), v.clone())).collect();
                fields.push(("compressed_bytes", best.to_string()));
                fields.push(("tried", json(&sizes)));
                fields.push(("seconds", format!("{:.1}", t0.elapsed().as_secs_f64())));
            }
            eprintln!("{}", json(&fields));
        }
        Command::Disasm { input, output, data } => {
            let text = disasm(&read_script(&input)?, data).map_err(|e| e.to_string())?;
            write_text(&output, &text)?;
        }
        Command::Attribute { input, plain, labels } => {
            let ranges = read_ranges(&labels)?;
            let a = attribute(&read_script(&input)?, &read_script(&Some(plain))?, &ranges)?;
            println!("{}", attribution_json(&a));
        }
        Command::NearDuplicates { input, top, max_varying, json: as_json } => {
            let found = near_duplicates(&read_script(&input)?, max_varying, top).map_err(|e| e.to_string())?;
            if as_json {
                let items: Vec<String> = found.iter().map(near_json).collect();
                println!("[\n  {}\n]", items.join(",\n  "));
            } else {
                print!("{}", near_text(&found));
            }
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
