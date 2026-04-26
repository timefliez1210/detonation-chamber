//! Generates shell completions for the `detonate` CLI.
//!
//! Usage:
//!   cargo run --bin generate-completions -- bash > detonate.bash
//!   cargo run --bin generate-completions -- zsh  > _detonate
//!   cargo run --bin generate-completions -- fish > detonate.fish

use clap::{Command, Parser};
use clap_complete::{generate, Shell};
use std::io;

#[derive(Parser)]
#[command(name = "generate-completions")]
struct Args {
    shell: Shell,
}

fn main() {
    let args = Args::parse();
    let mut cmd = detonation_tool_cli();
    generate(args.shell, &mut cmd, "detonate", &mut io::stdout());
}

/// Mirror of the real CLI so completions match exactly.
fn detonation_tool_cli() -> Command {
    clap::Command::new("detonate")
        .version("0.1.0")
        .about("Detect prompt injection by running untrusted payloads in a honeypot sandbox")
        .arg(
            clap::Arg::new("payload")
                .help("Untrusted payload to analyze")
                .num_args(0..=1),
        )
        .arg(
            clap::Arg::new("payload-file")
                .long("payload-file")
                .value_name("FILE")
                .help("Read payload from file"),
        )
        .arg(
            clap::Arg::new("output")
                .long("output")
                .default_value("json")
                .help("Output format: json, human, quiet"),
        )
        .arg(
            clap::Arg::new("provider")
                .long("provider")
                .value_name("PROVIDER")
                .help("LLM provider: ollama, openai, anthropic"),
        )
        .arg(
            clap::Arg::new("model")
                .long("model")
                .value_name("MODEL")
                .help("LLM model name"),
        )
        .arg(
            clap::Arg::new("max-turns")
                .long("max-turns")
                .default_value("10")
                .help("Max conversation turns"),
        )
        .arg(
            clap::Arg::new("canaries")
                .long("canaries")
                .default_value("8")
                .help("Number of canary secrets"),
        )
        .arg(
            clap::Arg::new("timeout")
                .long("timeout")
                .default_value("120")
                .help("Timeout in seconds"),
        )
        .arg(
            clap::Arg::new("no-traffic-review")
                .long("no-traffic-review")
                .action(clap::ArgAction::SetTrue)
                .help("Disable LLM traffic review"),
        )
        .arg(
            clap::Arg::new("firecracker")
                .long("firecracker")
                .action(clap::ArgAction::SetTrue)
                .help("Use Firecracker microVM"),
        )
        .arg(
            clap::Arg::new("vm-assets-dir")
                .long("vm-assets-dir")
                .default_value("./vm_assets")
                .help("Firecracker assets directory"),
        )
        .arg(
            clap::Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Verbose output"),
        )
}
