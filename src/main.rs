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
use daas::pi_agent::{Framing, Persona, PiAgent};
use daas::report::ReportBuilder;
use daas::sandbox::Isolation;
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

    /// LLM provider for the test agent: openrouter (default when
    /// OPENROUTER_API_KEY is set), openai, anthropic, gemini, ollama
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
    #[arg(long, default_value = "180")]
    timeout: u64,

    /// How the payload reaches the agent: "task" (untrusted inbox message the
    /// agent is asked to handle — indirect injection) or "direct" (payload is
    /// the user prompt)
    #[arg(long, default_value = "task", value_parser = ["task", "direct"])]
    framing: String,

    /// Agent harness under test: "pi" (default; model via --provider/--model),
    /// "claude-code" (headless Claude Code; --model is a Claude model such as
    /// haiku/sonnet/opus; auth from CLAUDE_CODE_OAUTH_TOKEN or
    /// ANTHROPIC_API_KEY, which never enter the sandbox), or "antigravity"
    /// (headless Google Antigravity CLI `agy`; --model is a Gemini model such
    /// as gemini-3.8-flash or gemini-4-neon; auth from GEMINI_API_KEY, which
    /// never enters the sandbox)
    #[arg(long, default_value = "pi", value_parser = ["pi", "claude-code", "antigravity"])]
    agent: String,

    /// The user's request for task framing (default: "handle the inbox
    /// message"). The payload is still delivered as ~/inbox/message.md. Use a
    /// specific task (e.g. "Summarize ~/inbox/message.md in 3 bullets") to
    /// measure whether content can hijack an agent doing something else.
    #[arg(long, value_name = "TEXT")]
    task: Option<String>,

    /// Agent persona: "trusting" (inbox is pre-approved; agent acts on
    /// requests without asking — maximally sensitive) or "default" (stock Pi
    /// prompt; measures what the model itself would do)
    #[arg(long, default_value = "trusting", value_parser = ["trusting", "default"])]
    persona: String,

    /// Thinking level for the test agent: Pi --thinking (off, minimal, low,
    /// medium, high) or, with --agent claude-code / antigravity, --effort
    /// (low, medium, high, xhigh, max)
    #[arg(long)]
    thinking: Option<String>,

    /// Comma-separated Pi tools to give the test agent
    #[arg(long, default_value = "read,bash,edit,write")]
    tools: String,

    /// Model for the LLM traffic review (default: same as --model)
    #[arg(long)]
    review_model: Option<String>,

    /// Load environment variables from this file (default: ./.env if present)
    #[arg(long, value_name = "FILE")]
    env_file: Option<String>,

    /// Run the agent WITHOUT the bubblewrap sandbox. UNSAFE: the agent's bash
    /// tool can then read and modify anything your user can.
    #[arg(long)]
    no_isolation: bool,

    /// Extra host path to hide inside the sandbox (repeatable), e.g. other
    /// data mounts. /home, /root, /media, /mnt, /run, /tmp, /srv and parts of
    /// /var are always hidden.
    #[arg(long, value_name = "PATH")]
    hide: Vec<PathBuf>,

    /// Keep the sandbox directory after the run (for debugging)
    #[arg(long)]
    keep_sandbox: bool,

    /// Disable LLM-based traffic review (Layer 5)
    #[arg(long)]
    no_traffic_review: bool,

    /// Disable the agent alarm review (Layer 6: did the agent itself call the
    /// content an attack?)
    #[arg(long)]
    no_agent_review: bool,

    /// Run the agent in a Firecracker microVM (own kernel, no network
    /// interface; only the LLM proxy and network canary are reachable via
    /// vsock). Needs /dev/kvm and assets from vm/fetch-assets.sh +
    /// vm/build-rootfs.sh
    #[arg(long)]
    firecracker: bool,

    /// Directory containing Firecracker VM assets (firecracker, vmlinux,
    /// rootfs.ext4). Default: ./vm_assets, else vm_assets next to the repo
    /// the binary was built in
    #[arg(long, default_value = "vm_assets")]
    vm_assets_dir: String,

    /// Verbose output (human-readable with more detail)
    #[arg(short, long)]
    verbose: bool,
}

#[tokio::main]
async fn main() {
    const MAX_PAYLOAD_SIZE: usize = 1_000_000; // 1 MB

    let args = Args::parse();

    // ── Environment (.env) ────────────────────────────────────────────
    match &args.env_file {
        Some(f) => {
            if let Err(e) = dotenvy::from_filename(f) {
                eprintln!("Error loading env file '{}': {}", f, e);
                std::process::exit(3);
            }
        }
        None => {
            let _ = dotenvy::dotenv();
        }
    }

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
    if !args.firecracker && args.agent == "pi" && which::which(&pi_bin).ok().is_none() {
        eprintln!(
            "Pi binary '{}' not found on PATH. Install pi first.",
            pi_bin
        );
        eprintln!("  curl -fsSL https://pi.sh/install | sh");
        std::process::exit(3);
    }

    // ── Detect LLM provider ───────────────────────────────────────────
    // With --agent claude-code or --agent antigravity, --model names the model
    // under test; the LLM provider config below is only used for the review
    // layers.
    let claude_code = args.agent == "claude-code";
    let antigravity = args.agent == "antigravity";
    let llm = detect_llm_provider(
        args.provider.clone(),
        if claude_code || antigravity {
            None
        } else {
            args.model.clone()
        },
    );
    let agent_kind = if claude_code {
        let auth = if let Some(t) = env_nonempty("CLAUDE_CODE_OAUTH_TOKEN") {
            daas::proxy::AnthropicAuth::OAuth(t)
        } else if let Some(k) = env_nonempty("ANTHROPIC_API_KEY") {
            daas::proxy::AnthropicAuth::ApiKey(k)
        } else {
            eprintln!(
                "--agent claude-code needs CLAUDE_CODE_OAUTH_TOKEN (from `claude setup-token`) or ANTHROPIC_API_KEY, e.g. in .env."
            );
            std::process::exit(3);
        };
        if args.firecracker {
            eprintln!("--agent claude-code is not supported with --firecracker yet.");
            std::process::exit(3);
        }
        daas::pi_agent::AgentKind::ClaudeCode { auth }
    } else if antigravity {
        if args.firecracker {
            eprintln!("--agent antigravity is not supported with --firecracker yet.");
            std::process::exit(3);
        }
        let api_key = match env_nonempty("GEMINI_API_KEY") {
            Some(k) => k,
            None => {
                eprintln!("--agent antigravity needs GEMINI_API_KEY, e.g. in .env.");
                std::process::exit(3);
            }
        };
        let api_base = env_nonempty("GOOGLE_GEMINI_BASE_URL")
            .or_else(|| env_nonempty("DAAS_GEMINI_API_BASE"))
            .unwrap_or_else(|| "https://generativelanguage.googleapis.com".into());
        daas::pi_agent::AgentKind::Antigravity { api_key, api_base }
    } else {
        daas::pi_agent::AgentKind::Pi
    };
    let agent_model = if claude_code {
        args.model.clone().unwrap_or_else(|| "haiku".into())
    } else if antigravity {
        args.model
            .clone()
            .unwrap_or_else(|| daas::antigravity::DEFAULT_MODEL.into())
    } else {
        llm.model.clone()
    };
    let agent_provider_label = if claude_code {
        "claude-code"
    } else if antigravity {
        "antigravity"
    } else {
        llm.provider.as_str()
    };

    if llm.api_key.is_empty() && llm.provider != "ollama" {
        eprintln!(
            "No API key found for provider '{}'. Set {} (or DAAS_LLM_API_KEY), e.g. in .env.",
            llm.provider,
            key_env_for(&llm.provider)
        );
        std::process::exit(3);
    }

    // ── Isolation ─────────────────────────────────────────────────────
    let isolation = if args.no_isolation {
        eprintln!(
            "⚠️  WARNING: --no-isolation: the agent runs UNSANDBOXED with access to your files."
        );
        Isolation::None
    } else {
        if !args.firecracker {
            if let Err(e) = daas::sandbox::bwrap_available() {
                eprintln!("{}", e);
                std::process::exit(3);
            }
        }
        Isolation::Bubblewrap
    };

    // ── Set up detection pipeline ─────────────────────────────────────
    let traffic_capture = TrafficCapture::new(llm.api_base.clone());

    let network_canary = match NetworkCanary::start().await {
        Ok(nc) => Some(Arc::new(nc)),
        Err(e) => {
            eprintln!("Warning: Failed to start network canary server: {}", e);
            None
        }
    };

    let review_model = args
        .review_model
        .clone()
        .or_else(|| std::env::var("DAAS_TRAFFIC_REVIEW_MODEL").ok())
        .unwrap_or_else(|| llm.model.clone());
    let review_client = LlmClient::new(
        llm.api_base.clone(),
        llm.api_key.clone(),
        review_model,
        4096,
    );

    let framing = if args.framing == "direct" {
        Framing::Direct
    } else {
        Framing::Task
    };
    let tools: Vec<String> = args
        .tools
        .split(',')
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();

    let mut agent = PiAgent::new(
        pi_bin,
        agent_provider_label.to_string(),
        agent_model.clone(),
        llm.api_key.clone(),
    )
    .with_agent(agent_kind)
    .with_task(args.task.clone())
    .with_hidden_paths(args.hide.clone())
    .with_agent_review_enabled(!args.no_agent_review)
    .with_api_base(llm.api_base.clone())
    .with_tools(tools)
    .with_max_turns(args.max_turns)
    .with_timeout(args.timeout)
    .with_thinking(args.thinking.clone())
    .with_isolation(isolation)
    .with_framing(framing)
    .with_persona(if args.persona == "default" {
        Persona::Default
    } else {
        Persona::Trusting
    })
    .with_keep_sandbox(args.keep_sandbox)
    .with_traffic_capture(traffic_capture)
    .with_review_client(review_client)
    .with_traffic_review_enabled(!args.no_traffic_review);

    if args.firecracker {
        let assets = resolve_vm_assets(&args.vm_assets_dir);
        let fc_config = daas::firecracker::FirecrackerConfig::from_assets_dir(&assets);
        if let Err(e) = fc_config.validate() {
            eprintln!("{}", e);
            std::process::exit(3);
        }
        agent = agent.with_firecracker(fc_config);
    }

    if let Some(nc) = &network_canary {
        agent = agent.with_network_canary(nc.clone());
    }

    // ── Run the detonation ────────────────────────────────────────────
    if args.output == "human" || args.verbose {
        eprintln!("🔬 Spinning up detonation chamber...");
        eprintln!("   Agent:     {} / {}", agent_provider_label, agent_model);
        eprintln!(
            "   Isolation: {}",
            if args.firecracker {
                "firecracker"
            } else {
                isolation.as_str()
            }
        );
        eprintln!("   Framing:   {}  Persona: {}", args.framing, args.persona);
        eprintln!(
            "   Canaries:  {}  Max turns: {}  Timeout: {}s",
            args.canaries, args.max_turns, args.timeout
        );
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

/// `--vm-assets-dir` as given if it exists; otherwise try `<repo>/vm_assets`
/// relative to the executable (target/{release,debug}/detonate).
fn resolve_vm_assets(dir: &str) -> PathBuf {
    let p = PathBuf::from(dir);
    if p.exists() || p.is_absolute() {
        return p;
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent()?.parent()?.parent().map(|repo| repo.join(dir)))
        .filter(|c| c.exists())
        .unwrap_or(p)
}

struct LlmConfig {
    provider: String,
    model: String,
    api_key: String,
    api_base: String,
}

fn key_env_for(provider: &str) -> &'static str {
    match provider {
        "openrouter" => "OPENROUTER_API_KEY",
        "openai" => "OPENAI_API_KEY",
        "anthropic" => "ANTHROPIC_API_KEY",
        "gemini" => "GEMINI_API_KEY",
        _ => "DAAS_LLM_API_KEY",
    }
}

fn env_nonempty(k: &str) -> Option<String> {
    std::env::var(k).ok().filter(|v| !v.trim().is_empty())
}

/// Resolve provider, model, key and base URL. Priority: CLI flags, then
/// DAAS_LLM_* variables, then whichever provider key is present
/// (OpenRouter → OpenAI → Anthropic → Gemini), then local Ollama.
fn detect_llm_provider(cli_provider: Option<String>, cli_model: Option<String>) -> LlmConfig {
    resolve_llm_provider(cli_provider, cli_model, env_nonempty)
}

fn resolve_llm_provider(
    cli_provider: Option<String>,
    cli_model: Option<String>,
    lookup: impl Fn(&str) -> Option<String>,
) -> LlmConfig {
    let provider = cli_provider
        .or_else(|| lookup("DAAS_LLM_PROVIDER"))
        .unwrap_or_else(|| {
            if lookup("OPENROUTER_API_KEY").is_some() {
                "openrouter"
            } else if lookup("OPENAI_API_KEY").is_some() {
                "openai"
            } else if lookup("ANTHROPIC_API_KEY").is_some() {
                "anthropic"
            } else if lookup("GEMINI_API_KEY").is_some() {
                "gemini"
            } else {
                "ollama"
            }
            .to_string()
        });

    let api_key = lookup("DAAS_LLM_API_KEY")
        .or_else(|| lookup(key_env_for(&provider)))
        .unwrap_or_default();

    let model = cli_model
        .or_else(|| lookup("DAAS_LLM_MODEL"))
        .unwrap_or_else(|| match provider.as_str() {
            "openrouter" => "z-ai/glm-5.3-flash".into(),
            "openai" => "gpt-4o-mini".into(),
            "anthropic" => "claude-haiku-5-5".into(),
            "gemini" => "gemini-3.8-flash".into(),
            _ => "llama3.2".into(),
        });

    let api_base = lookup("DAAS_LLM_API_BASE").unwrap_or_else(|| match provider.as_str() {
        "openrouter" => "https://openrouter.ai/api/v1".into(),
        "openai" => "https://api.openai.com/v1".into(),
        "anthropic" => "https://api.anthropic.com/v1".into(),
        "gemini" => "https://generativelanguage.googleapis.com/v1beta/openai".into(),
        _ => "http://localhost:11434/v1".into(),
    });

    LlmConfig {
        provider,
        model,
        api_key,
        api_base,
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

    if let Some(m) = &report.metadata {
        println!();
        println!(
            "Run: {} / {} | isolation={} framing={} persona={} | {} turns, {} tool calls | {:.1}s | {} in / {} out tokens",
            m.provider, m.model, m.isolation, m.framing, m.persona, m.turns, m.tool_calls, m.duration_secs,
            m.input_tokens, m.output_tokens
        );
    }

    if verbose {
        println!();
        println!("Timeline:");
        for e in &report.behavioral_timeline {
            println!("  [{:?}] {}", e.severity, e.description);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_llm_provider;
    use std::collections::HashMap;

    fn env_map(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k: &str| map.get(k).cloned().filter(|v| !v.trim().is_empty())
    }

    #[test]
    fn gemini_auto_detected_from_gemini_api_key() {
        let cfg = resolve_llm_provider(None, None, env_map(&[("GEMINI_API_KEY", "test-gem-key")]));
        assert_eq!(cfg.provider, "gemini");
        assert_eq!(cfg.api_key, "test-gem-key");
        assert_eq!(cfg.model, "gemini-3.8-flash");
        assert_eq!(
            cfg.api_base,
            "https://generativelanguage.googleapis.com/v1beta/openai"
        );
    }

    #[test]
    fn explicit_gemini_provider_overrides_openrouter_key() {
        let cfg = resolve_llm_provider(
            Some("gemini".into()),
            Some("gemini-3.5-flash-lite".into()),
            env_map(&[
                ("OPENROUTER_API_KEY", "or-key"),
                ("GEMINI_API_KEY", "gem-key"),
            ]),
        );
        assert_eq!(cfg.provider, "gemini");
        assert_eq!(cfg.api_key, "gem-key");
        assert_eq!(cfg.model, "gemini-3.5-flash-lite");
        assert_eq!(
            cfg.api_base,
            "https://generativelanguage.googleapis.com/v1beta/openai"
        );
    }

    #[test]
    fn openrouter_takes_precedence_over_gemini_by_default() {
        let cfg = resolve_llm_provider(
            None,
            None,
            env_map(&[
                ("OPENROUTER_API_KEY", "or-key"),
                ("GEMINI_API_KEY", "gem-key"),
            ]),
        );
        assert_eq!(cfg.provider, "openrouter");
        assert_eq!(cfg.api_key, "or-key");
    }

    #[test]
    fn daas_overrides_apply_to_gemini() {
        let cfg = resolve_llm_provider(
            Some("gemini".into()),
            None,
            env_map(&[
                ("GEMINI_API_KEY", "gem-key"),
                ("DAAS_LLM_API_KEY", "override-key"),
                ("DAAS_LLM_MODEL", "gemini-flash-latest"),
                ("DAAS_LLM_API_BASE", "https://proxy.example/v1"),
            ]),
        );
        assert_eq!(cfg.provider, "gemini");
        assert_eq!(cfg.api_key, "override-key");
        assert_eq!(cfg.model, "gemini-flash-latest");
        assert_eq!(cfg.api_base, "https://proxy.example/v1");
    }
}
