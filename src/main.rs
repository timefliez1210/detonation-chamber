//! Detonation Tool — prompt injection detection CLI.
//!
//! Spins up a real Pi agent in a honeypot sandbox environment and monitors
//! for exfiltration attempts across multiple detection layers.
//!
//! Exit codes:
//!   0 = safe (no exfiltration detected)
//!   1 = suspicious (some indicators but no confirmed exfil)
//!   2 = malicious (confirmed exfiltration detected)
//!   3 = error (internal failure)

use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use daas::behavioral::NetworkCanary;
use daas::llm::LlmClient;
use daas::pi_agent::PiAgent;
use daas::report::ReportBuilder;
use daas::traffic::TrafficCapture;
use daas::types::{DetonationReport, Verdict};

#[derive(Parser, Debug)]
#[command(
    name = "detonate",
    version,
    about = "Detect prompt injection by running untrusted payloads in a honeypot sandbox"
)]
struct Args {
    /// Untrusted payload to analyze (text, code, or document content)
    payload: Option<String>,

    /// Read payload from file instead of argument
    #[arg(long, value_name = "FILE")]
    payload_file: Option<String>,

    /// Output format: json (default), human, or quiet (exit code only)
    #[arg(long, default_value = "json")]
    output: String,

    /// LLM provider for the test agent (ollama, openai, anthropic)
    #[arg(long)]
    provider: Option<String>,

    /// LLM model for the test agent
    #[arg(long)]
    model: Option<String>,

    /// Max conversation turns for the test agent
    #[arg(long, default_value = "10")]
    max_turns: usize,

    /// Number of canary secrets to plant
    #[arg(long, default_value = "8")]
    canaries: usize,

    /// Timeout in seconds for the detonation
    #[arg(long, default_value = "120")]
    timeout: u64,

    /// Disable LLM-based traffic review (Layer 3)
    #[arg(long)]
    no_traffic_review: bool,

    /// Spin up a real Firecracker microVM for the detonation agent
    #[arg(long)]
    firecracker: bool,

    /// Directory containing Firecracker VM assets (vmlinux, rootfs.ext4, id_rsa)
    #[arg(long, default_value = "./vm_assets")]
    vm_assets_dir: String,

    /// Verbose output (human-readable with more detail)
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    const MAX_PAYLOAD_SIZE: usize = 1_000_000; // 1 MB

    let args = Args::parse();

    // ── Read payload ──────────────────────────────────────────────────
    let payload = if let Some(ref file) = args.payload_file {
        match std::fs::read_to_string(file) {
            Ok(content) => content,
            Err(e) => {
                eprintln!("Error reading payload file '{}': {}", file, e);
                std::process::exit(3);
            }
        }
    } else if let Some(ref payload) = args.payload {
        payload.clone()
    } else {
        // Read from stdin
        let mut input = String::new();
        match std::io::stdin().read_to_string(&mut input) {
            Ok(0) => {
                eprintln!("No payload provided. Use: detonate \"payload\" or pipe to stdin");
                std::process::exit(3);
            }
            Ok(_) => input,
            Err(e) => {
                eprintln!("Error reading stdin: {}", e);
                std::process::exit(3);
            }
        }
    };

    if payload.len() > MAX_PAYLOAD_SIZE {
        eprintln!(
            "Payload too large: {} bytes (max: {} bytes)",
            payload.len(),
            MAX_PAYLOAD_SIZE
        );
        std::process::exit(3);
    }

    // ── Detect Pi binary ──────────────────────────────────────────────
    let pi_bin = std::env::var("PI_BIN").unwrap_or_else(|_| "pi".into());
    if !args.firecracker && which::which(&pi_bin).ok().is_none() {
        eprintln!(
            "Pi binary '{}' not found on PATH. Install pi first.",
            pi_bin
        );
        eprintln!("  curl -fsSL https://pi.sh/install | sh");
        std::process::exit(3);
    }

    // ── Detect LLM provider ───────────────────────────────────────────
    let (provider, model, api_key) = detect_llm_provider(args.provider, args.model);

    if api_key.is_empty() && provider != "ollama" {
        eprintln!(
            "No API key found for provider '{}'. Set DAAS_LLM_API_KEY or use Ollama.",
            provider
        );
        std::process::exit(3);
    }

    // ── Set up detection pipeline ─────────────────────────────────────
    let llm_api_base = get_api_base(&provider);

    // Layer 4: Traffic capture
    let traffic_capture = TrafficCapture::new(llm_api_base.clone());

    // Layer 2: Network canary HTTP server
    let network_canary = match NetworkCanary::start().await {
        Ok(nc) => {
            eprintln!("   Network canary: http://127.0.0.1:{}", nc.port);
            Some(Arc::new(nc))
        }
        Err(e) => {
            eprintln!("Warning: Failed to start network canary server: {}", e);
            None
        }
    };

    // Layer 3: Traffic reviewer (LLM-based)
    let review_model = std::env::var("DAAS_TRAFFIC_REVIEW_MODEL").unwrap_or_else(|_| model.clone());
    let review_client = LlmClient::new(llm_api_base.clone(), api_key.clone(), review_model, 2048);

    // Build Pi agent with all layers
    let mut agent = PiAgent::new(pi_bin, provider.clone(), model.clone(), api_key.clone())
        .with_max_turns(args.max_turns)
        .with_timeout(args.timeout)
        .with_traffic_capture(traffic_capture)
        .with_review_client(review_client)
        .with_traffic_review_enabled(!args.no_traffic_review);

    if args.firecracker {
        let assets = PathBuf::from(&args.vm_assets_dir);
        let kernel = assets.join("vmlinux");
        let rootfs = assets.join("rootfs.ext4");
        let ssh_key = assets.join("id_rsa");

        if !kernel.exists() {
            eprintln!("Firecracker kernel not found: {}", kernel.display());
            eprintln!("Run without --firecracker or build VM assets first.");
            std::process::exit(3);
        }
        if !rootfs.exists() {
            eprintln!("Firecracker rootfs not found: {}", rootfs.display());
            std::process::exit(3);
        }
        if !ssh_key.exists() {
            eprintln!("Firecracker SSH key not found: {}", ssh_key.display());
            std::process::exit(3);
        }

        let fc_config = daas::firecracker::FirecrackerConfig {
            kernel_path: kernel,
            rootfs_path: rootfs,
            ssh_key_path: ssh_key,
            ..Default::default()
        };

        agent = agent.with_firecracker(fc_config);
        if args.output == "human" || args.verbose {
            eprintln!("   Firecracker VM: enabled");
        }
    }

    if let Some(nc) = &network_canary {
        agent = agent.with_network_canary(nc.clone());
    }

    // ── Run the detonation ────────────────────────────────────────────
    if args.output == "human" || args.verbose {
        eprintln!("🔬 Spinning up detonation chamber...");
        eprintln!("   Canaries: {}", args.canaries);
        eprintln!("   Max turns: {}", args.max_turns);
        if network_canary.is_some() {
            eprintln!("   Network canary: active");
        }
        eprintln!();
    }

    let result = agent.detonate(&payload, args.canaries).await;

    // ── Build report ──────────────────────────────────────────────────
    let report = ReportBuilder::from_pi_result(&result);

    // ── Output ────────────────────────────────────────────────────────
    let print_json = |report: &DetonationReport| match serde_json::to_string_pretty(report) {
        Ok(json) => println!("{}", json),
        Err(e) => {
            eprintln!("Error serializing report to JSON: {}", e);
            eprintln!("Verdict: {:?}", report.verdict);
            eprintln!("Confidence: {:.1}%", report.confidence * 100.0);
            std::process::exit(3);
        }
    };

    match args.output.as_str() {
        "json" => print_json(&report),
        "human" => {
            print_human_report(&report, args.verbose);
        }
        "quiet" => {
            // No output, just exit code
        }
        _ => print_json(&report),
    }

    if args.verbose && args.output == "json" {
        eprintln!();
        eprintln!("Verdict: {:?}", report.verdict);
        eprintln!("Confidence: {:.1}%", report.confidence * 100.0);
        eprintln!("Exfiltration events: {}", report.exfiltration_events.len());
    }

    // ── Exit with appropriate code ────────────────────────────────────
    let exit_code = match report.verdict {
        Verdict::Safe => 0,
        Verdict::Suspicious => 1,
        Verdict::Malicious => 2,
        Verdict::Error => 3,
    };
    std::process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// LLM provider detection
// ---------------------------------------------------------------------------

/// Detect available LLM provider. Priority:
/// 1. CLI flags
/// 2. Environment variables
/// 3. Auto-detect local Ollama
fn detect_llm_provider(
    cli_provider: Option<String>,
    cli_model: Option<String>,
) -> (String, String, String) {
    let api_key = std::env::var("DAAS_LLM_API_KEY")
        .or_else(|_| std::env::var("OPENAI_API_KEY"))
        .or_else(|_| std::env::var("ANTHROPIC_API_KEY"))
        .or_else(|_| std::env::var("OLLAMA_API"))
        .unwrap_or_default();

    let provider = cli_provider.unwrap_or_else(|| {
        std::env::var("DAAS_LLM_PROVIDER").unwrap_or_else(|_| {
            if !api_key.is_empty() {
                if api_key.starts_with("sk-ant") {
                    "anthropic"
                } else {
                    "openai"
                }
            } else {
                "ollama"
            }
            .to_string()
        })
    });

    let model = cli_model.unwrap_or_else(|| {
        std::env::var("DAAS_LLM_MODEL").unwrap_or_else(|_| match provider.as_str() {
            "openai" => "gpt-4o-mini".into(),
            "anthropic" => "claude-sonnet-4-20250514".into(),
            _ => "llama3.2".into(),
        })
    });

    (provider, model, api_key)
}

/// Get the API base URL for the provider.
fn get_api_base(provider: &str) -> String {
    if let Ok(base) = std::env::var("DAAS_LLM_API_BASE") {
        return base;
    }
    match provider {
        "openai" => "https://api.openai.com/v1".into(),
        "anthropic" => "https://api.anthropic.com/v1".into(),
        _ => "http://localhost:11434/v1".into(),
    }
}

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

fn print_human_report(report: &DetonationReport, verbose: bool) {
    let icon = match report.verdict {
        Verdict::Safe => "✅",
        Verdict::Suspicious => "⚠️",
        Verdict::Malicious => "🚨",
        Verdict::Error => "❌",
    };

    println!("{} Verdict: {:?}", icon, report.verdict);
    println!("   Confidence: {:.0}%", report.confidence * 100.0);
    println!();

    if verbose || report.verdict != Verdict::Safe {
        println!("{}", report.payload_analysis);
        println!();
    }

    if report.exfiltration_events.is_empty() {
        println!("No exfiltration events detected.");
    } else {
        println!("Exfiltration events: {}", report.exfiltration_events.len());
        for event in &report.exfiltration_events {
            println!("  - {} via {:?}", event.secret_type.label(), event.channel);
        }
    }
}
