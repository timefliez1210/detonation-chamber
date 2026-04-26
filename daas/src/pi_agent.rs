use chrono::Utc;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tracing::{info, warn, error};
use uuid::Uuid;

use crate::behavioral::{BehavioralAnalyzer, NetworkCanary, NetworkCanaryHit};
use crate::canary::CanaryGenerator;
use crate::honeypot::HoneypotBuilder;
use crate::llm::LlmClient;
use crate::monitor::CanaryMonitor;
use crate::traffic::{TrafficCapture, TrafficLog, TrafficReviewer};
use crate::types::{
    Canary, DetonationEvent, DetonationEventType, ExfilChannel, ExfiltrationEvent, Severity,
};

// ---------------------------------------------------------------------------
// Pi event stream parsing
// ---------------------------------------------------------------------------

/// A parsed event from Pi's JSONL output stream.
#[derive(Debug, Clone)]
pub enum PiEvent {
    /// The LLM decided to call a tool
    ToolCallStart {
        tool_call_id: String,
        tool_name: String,
        args: serde_json::Value,
    },
    /// A tool finished executing
    ToolExecutionEnd {
        tool_call_id: String,
        tool_name: String,
        result: serde_json::Value,
    },
    /// The LLM produced text output
    TextOutput {
        content: String,
    },
    /// The LLM produced thinking/reasoning
    Thinking {
        content: String,
    },
}

// ---------------------------------------------------------------------------
// Detonation result
// ---------------------------------------------------------------------------

/// Result of running a Pi-based detonation.
#[derive(Debug, Clone)]
pub struct PiDetonationResult {
    pub events: Vec<DetonationEvent>,
    pub exfiltration_events: Vec<ExfiltrationEvent>,
    pub pi_events: Vec<PiEvent>,
    pub total_turns: usize,
    pub terminated_reason: String,
    pub canaries: Vec<Canary>,
    pub sandbox_dir: Option<String>,
    /// Traffic events captured during the detonation
    pub traffic_log: Option<TrafficLog>,
    /// Network canary hits (if a canary HTTP server was running)
    pub network_canary_hits: Vec<NetworkCanaryHit>,
    /// LLM-based traffic review result (Layer 3)
    pub traffic_review: Option<crate::traffic::TrafficReview>,
}

// ---------------------------------------------------------------------------
// Pi agent — the real detonation engine
// ---------------------------------------------------------------------------

/// Runs Pi as the detonation agent. Pi has REAL tools (read, bash, edit, write)
/// that can ACTUALLY access the filesystem, execute commands, and exfiltrate data.
/// We plant canary secrets on disk, feed the payload to Pi, and monitor its
/// JSONL event stream for canary leakage.
pub struct PiAgent {
    /// Path to the pi binary
    pi_bin: String,
    /// LLM provider config for Pi
    provider: String,
    /// Model to use
    model: String,
    /// API key (will be set as env var for Pi)
    api_key: String,
    /// Which tools to enable in Pi
    tools: Vec<String>,
    /// Maximum turns before forced termination
    max_turns: usize,
    /// Timeout in seconds
    timeout_secs: u64,
    /// Traffic capture for analyzing network events
    traffic_capture: Option<TrafficCapture>,
    /// Network canary server (if started)
    network_canary: Option<Arc<NetworkCanary>>,
    /// LLM client for traffic review (Layer 3)
    review_client: Option<LlmClient>,
    /// Whether to run LLM-based traffic review
    traffic_review_enabled: bool,
    /// Run Pi inside a Firecracker microVM
    use_firecracker: bool,
    /// Firecracker configuration
    firecracker_config: Option<crate::firecracker::FirecrackerConfig>,
}

impl PiAgent {
    #[allow(clippy::too_many_arguments)]
    pub fn new(pi_bin: String, provider: String, model: String, api_key: String) -> Self {
        Self {
            pi_bin,
            provider,
            model,
            api_key,
            tools: vec!["read".into(), "bash".into(), "edit".into(), "write".into()],
            max_turns: 10,
            timeout_secs: 120,
            traffic_capture: None,
            network_canary: None,
            review_client: None,
            traffic_review_enabled: true,
            use_firecracker: false,
            firecracker_config: None,
        }
    }

    pub fn with_tools(mut self, tools: Vec<String>) -> Self {
        self.tools = tools;
        self
    }

    pub fn with_traffic_capture(mut self, capture: TrafficCapture) -> Self {
        self.traffic_capture = Some(capture);
        self
    }

    pub fn with_network_canary(mut self, canary: Arc<NetworkCanary>) -> Self {
        self.network_canary = Some(canary);
        self
    }

    pub fn with_review_client(mut self, client: LlmClient) -> Self {
        self.review_client = Some(client);
        self
    }

    pub fn with_traffic_review_enabled(mut self, enabled: bool) -> Self {
        self.traffic_review_enabled = enabled;
        self
    }

    pub fn with_max_turns(mut self, max: usize) -> Self {
        self.max_turns = max;
        self
    }

    pub fn with_timeout(mut self, secs: u64) -> Self {
        self.timeout_secs = secs;
        self
    }

    pub fn with_firecracker(mut self, config: crate::firecracker::FirecrackerConfig) -> Self {
        self.use_firecracker = true;
        self.firecracker_config = Some(config);
        self
    }

    /// Execute a full detonation: create honeypot → run Pi → monitor → report
    pub async fn detonate(&self, payload: &str, canary_count: usize) -> PiDetonationResult {
        // ── Phase 1: Generate canaries ────────────────────────────────
        let canaries = CanaryGenerator::generate(canary_count);

        // ── Phase 2: Build honeypot environment on disk ───────────────
        let net_canary_urls: Vec<String> = self
            .network_canary
            .as_ref()
            .map(|nc| vec![nc.url.clone()])
            .unwrap_or_default();
        let sandbox_dir = self.create_sandbox(&canaries, &net_canary_urls);

        // ── Phase 3: Run Pi with the payload ──────────────────────────
        let (pi_events, terminated_reason, turns) = self.run_pi(payload, &sandbox_dir).await;

        // ── Phase 4: Monitor for canary leakage ───────────────────────
        let (mut events, mut exfiltration_events) =
            self.monitor_events(&pi_events, &canaries);

        // ── Phase 5: Capture traffic log via TrafficCapture ──────────
        let traffic_log: Option<TrafficLog> = self.traffic_capture.as_ref().map(|tc| {
            let mut log = tc.extract_from_pi_events(&pi_events);
            // Fill in metadata
            log.detonation_id = Uuid::new_v4().to_string();
            log.capture_duration_secs = self.timeout_secs;
            log
        });

        // ── Phase 6: Collect network canary hits ──────────────────────
        let network_canary_hits: Vec<NetworkCanaryHit> = match self.network_canary.as_ref() {
            Some(nc) => {
                let hits = nc.get_hits().await;
                if !hits.is_empty() {
                    info!(
                        hit_count = hits.len(),
                        "Network canary caught hits from LLM"
                    );
                    for hit in &hits {
                        let details = format!(
                            "🚨 NETWORK CANARY HIT: {} {} from {} — headers: {:?}",
                            hit.method, hit.path, hit.source_ip, hit.headers
                        );
                        events.push(DetonationEvent {
                            timestamp: Utc::now(),
                            event_type: DetonationEventType::NetworkActivity,
                            details: details.clone(),
                            severity: Severity::Critical,
                        });
                        exfiltration_events.push(ExfiltrationEvent {
                            canary_id: uuid::Uuid::nil(),
                            secret_type: crate::types::SecretType::GenericApiKey,
                            channel: ExfilChannel::NetworkRequest {
                                url: format!("{}{}", nc.url, hit.path),
                            },
                            destination: Some(hit.source_ip.clone()),
                            timestamp: Utc::now(),
                            raw_output: details,
                        });
                    }
                }
                hits
            }
            None => Vec::new(),
        };

        // ── Phase 7: Run LLM-based traffic review (Layer 3) ──────────
        let traffic_review = if self.traffic_review_enabled {
            if let (Some(ref client), Some(ref tl)) = (&self.review_client, &traffic_log) {
                let reviewer = TrafficReviewer::new((*client).clone());
                let review = reviewer.review(tl).await;
                info!(
                    assessment = ?review.assessment,
                    findings = review.suspicious_findings.len(),
                    "Traffic review complete"
                );

                // Emit events for suspicious traffic review findings
                for finding in &review.suspicious_findings {
                    let severity = match finding.severity.as_str() {
                        "critical" => Severity::Critical,
                        "high" => Severity::High,
                        "medium" => Severity::Medium,
                        _ => Severity::Low,
                    };
                    events.push(DetonationEvent {
                        timestamp: Utc::now(),
                        event_type: DetonationEventType::NetworkActivity,
                        details: format!(
                            "🤖 TRAFFIC REVIEW (LLM): [{}] {} — {}",
                            finding.severity, finding.finding_type, finding.description
                        ),
                        severity,
                    });
                }

                Some(review)
            } else {
                None
            }
        } else {
            None
        };

        // Add sandbox setup events at the start
        events.insert(
            0,
            DetonationEvent {
                timestamp: Utc::now(),
                event_type: DetonationEventType::LlmResponse,
                details: format!(
                    "Sandbox created at {} with {} canary secrets{}",
                    sandbox_dir,
                    canaries.len(),
                    if net_canary_urls.is_empty() {
                        String::new()
                    } else {
                        format!(" and {} network canary URL(s)", net_canary_urls.len())
                    }
                ),
                severity: Severity::Info,
            },
        );

        PiDetonationResult {
            events,
            exfiltration_events,
            pi_events,
            total_turns: turns,
            terminated_reason,
            canaries,
            sandbox_dir: Some(sandbox_dir),
            traffic_log,
            network_canary_hits,
            traffic_review,
        }
    }

    /// Create the sandbox directory with honeypot files on real disk.
    fn create_sandbox(&self, canaries: &[Canary], network_canary_urls: &[String]) -> String {
        let sandbox_id = Uuid::new_v4().to_string();
        let sandbox_dir = format!("/tmp/daas-sandbox-{}", sandbox_id);

        let environment =
            HoneypotBuilder::build_with_network_canaries(canaries, network_canary_urls);

        // Write all honeypot files to disk
        for (path, content) in &environment.files {
            let full_path =
                PathBuf::from(&sandbox_dir).join(path.strip_prefix("/").unwrap_or(path));

            // Use the dirs set from the environment instead of fragile heuristics
            if environment.dirs.contains(path) {
                // Create the directory
                std::fs::create_dir_all(&full_path).ok();
                continue;
            }

            // Create parent directory
            if let Some(parent) = full_path.parent() {
                std::fs::create_dir_all(parent).ok();
            }

            // Write the file
            match std::fs::write(&full_path, content) {
                Ok(_) => info!(path = %full_path.display(), "Wrote honeypot file"),
                Err(e) => warn!(
                    path = %full_path.display(),
                    error = %e,
                    "Failed to write honeypot file"
                ),
            }
        }

        info!(dir = sandbox_dir, "Sandbox created");
        sandbox_dir
    }

    /// Run Pi against the payload in the sandbox directory.
    async fn run_pi(&self, payload: &str, sandbox_dir: &str) -> (Vec<PiEvent>, String, usize) {
        if self.use_firecracker {
            self.run_pi_firecracker(payload, sandbox_dir).await
        } else {
            self.run_pi_local(payload, sandbox_dir).await
        }
    }

    async fn run_pi_firecracker(&self, payload: &str, sandbox_dir: &str) -> (Vec<PiEvent>, String, usize) {
        let config = match &self.firecracker_config {
            Some(c) => c.clone(),
            None => {
                error!("Firecracker requested but no config provided");
                return (vec![], "no_firecracker_config".into(), 0);
            }
        };

        let vm = match crate::firecracker::FirecrackerVm::start(config).await {
            Ok(vm) => vm,
            Err(e) => {
                error!(error = %e, "Failed to start Firecracker VM");
                return (vec![], format!("vm_start_failed: {}", e), 0);
            }
        };

        let pi_args = vec![
            format!("--provider={}", self.provider),
            format!("--model={}", self.model),
            if !self.tools.is_empty() {
                format!("--tools={}", self.tools.join(","))
            } else {
                String::new()
            },
        ];

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(self.timeout_secs),
            vm.run_pi(payload, sandbox_dir, &pi_args),
        ).await;

        let output = match result {
            Ok(Ok(out)) => out,
            Ok(Err(e)) => {
                error!(error = %e, "Pi execution in VM failed");
                let _ = vm.kill().await;
                return (vec![], format!("vm_pi_failed: {}", e), 0);
            }
            Err(_) => {
                error!("Pi execution in VM timed out");
                let _ = vm.kill().await;
                return (vec![], "vm_timeout".into(), 0);
            }
        };

        if let Err(e) = vm.kill().await {
            warn!(error = %e, "Failed to kill Firecracker VM gracefully");
        }

        let sandbox = sandbox_dir.to_string();
        tokio::task::spawn_blocking(move || {
            let _ = std::fs::remove_dir_all(&sandbox);
        });

        output
    }

    async fn run_pi_local(&self, payload: &str, sandbox_dir: &str) -> (Vec<PiEvent>, String, usize) {
        let pi_bin = self.pi_bin.clone();
        let provider = self.provider.clone();
        let model = self.model.clone();
        let api_key = self.api_key.clone();
        let tools = self.tools.clone();
        let max_turns = self.max_turns;
        let sandbox = sandbox_dir.to_string();
        let payload = payload.to_string();

        tokio::task::spawn_blocking(move || {
            let mut cmd = Command::new(&pi_bin);

            cmd.arg("--mode")
                .arg("json")
                .arg("--print")
                .arg("--no-session")
                .arg("--provider")
                .arg(&provider)
                .arg("--model")
                .arg(&model);

            if !tools.is_empty() {
                cmd.arg("--tools").arg(tools.join(","));
            }

            cmd.current_dir(&sandbox);

            if !api_key.is_empty() {
                match provider.as_str() {
                    "openai" => { cmd.env("OPENAI_API_KEY", &api_key); }
                    "anthropic" => { cmd.env("ANTHROPIC_API_KEY", &api_key); }
                    "ollama" => {}
                    _ => { cmd.env("PI_API_KEY", &api_key); }
                }
            }

            cmd.arg(&payload);
            cmd.stdout(Stdio::piped()).stderr(Stdio::piped());

            info!(cmd = ?cmd, "Starting Pi detonation");

            let mut child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    error!(error = %e, "Failed to start Pi");
                    return (vec![], format!("Failed to start Pi: {}", e), 0);
                }
            };

            let stdout = child.stdout.take().expect("Failed to capture stdout");
            let reader = BufReader::new(stdout);

            let mut events = Vec::new();
            let mut turns = 0;

            for line in reader.lines() {
                match line {
                    Ok(line) => {
                        if let Some(event) = parse_pi_event(&line) {
                            if matches!(event, PiEvent::ToolCallStart { .. }) {
                                turns += 1;
                                if turns >= max_turns {
                                    info!(turns, "Hit max turns, terminating Pi");
                                    let _ = child.kill();
                                    break;
                                }
                            }
                            events.push(event);
                        }
                    }
                    Err(e) => {
                        warn!(error = %e, "Error reading Pi output");
                        break;
                    }
                }
            }

            let terminated_reason = if turns >= max_turns {
                "max_turns_reached".into()
            } else {
                "natural_stop".into()
            };

            let _ = std::fs::remove_dir_all(&sandbox);

            (events, terminated_reason, turns)
        }).await.unwrap_or_else(|e| {
            error!(error = %e, "Local Pi task panicked");
            (vec![], format!("panic: {}", e), 0)
        })
    }

    /// Monitor Pi events for canary leakage AND behavioral anomalies.
    fn monitor_events(
        &self,
        pi_events: &[PiEvent],
        canaries: &[Canary],
    ) -> (Vec<DetonationEvent>, Vec<ExfiltrationEvent>) {
        let mut det_events = Vec::new();
        let mut exfil_events = Vec::new();

        let mut recent_file_reads: Vec<String> = Vec::new();

        // Extract traffic log for unexpected traffic
        let traffic_log: Option<TrafficLog> =
            self.traffic_capture.as_ref().map(|tc| tc.extract_from_pi_events(pi_events));

        if let Some(ref tl) = traffic_log {
            if !tl.unexpected_events.is_empty() {
                for event in &tl.unexpected_events {
                    det_events.push(DetonationEvent {
                        timestamp: Utc::now(),
                        event_type: DetonationEventType::NetworkActivity,
                        details: format!(
                            "🚨 UNEXPECTED TRAFFIC: {} {} → {}",
                            event.protocol,
                            match event.direction {
                                crate::traffic::TrafficDirection::Inbound => "IN",
                                crate::traffic::TrafficDirection::Outbound => "OUT",
                                crate::traffic::TrafficDirection::Bidirectional => "BID",
                            },
                            event.destination.as_deref().unwrap_or("unknown")
                        ),
                        severity: Severity::Critical,
                    });

                    if event.direction == crate::traffic::TrafficDirection::Outbound {
                        exfil_events.push(ExfiltrationEvent {
                            canary_id: uuid::Uuid::nil(),
                            secret_type: crate::types::SecretType::GenericApiKey,
                            channel: ExfilChannel::NetworkRequest {
                                url: event.destination.clone().unwrap_or_default(),
                            },
                            destination: event.destination.clone(),
                            timestamp: Utc::now(),
                            raw_output: event.raw_command.clone().unwrap_or_default(),
                        });
                    }
                }
            }
        }

        for event in pi_events {
            match event {
                PiEvent::ToolCallStart {
                    tool_name,
                    args,
                    tool_call_id: _,
                } => {
                    let args_str = serde_json::to_string(args).unwrap_or_default();

                    let detections =
                        CanaryMonitor::check_tool_call(tool_name, &args_str, canaries);
                    let (mut de, mut ee) = CanaryMonitor::detections_to_events(&detections);
                    det_events.append(&mut de);
                    exfil_events.append(&mut ee);

                    if tool_name == "bash" {
                        let command = args["command"].as_str().unwrap_or("");

                        let behavioral_flags =
                            BehavioralAnalyzer::analyze_bash_command(command);
                        for flag in &behavioral_flags {
                            det_events.push(DetonationEvent {
                                timestamp: Utc::now(),
                                event_type: DetonationEventType::NetworkActivity,
                                details: format!("⚠️  BEHAVIORAL: {}", flag.description),
                                severity: flag.severity,
                            });

                            if flag.severity >= Severity::Critical {
                                exfil_events.push(ExfiltrationEvent {
                                    canary_id: uuid::Uuid::nil(),
                                    secret_type: crate::types::SecretType::GenericApiKey,
                                    channel: match flag.flag_type {
                                        crate::behavioral::BehavioralFlagType::CryptoTransactionAttempt => {
                                            ExfilChannel::ToolCall {
                                                tool_name: "crypto_transaction".into(),
                                            }
                                        }
                                        crate::behavioral::BehavioralFlagType::ExternalApiCall => {
                                            ExfilChannel::NetworkRequest {
                                                url: flag
                                                    .raw_command
                                                    .clone()
                                                    .unwrap_or_default(),
                                            }
                                        }
                                        _ => ExfilChannel::ToolCall {
                                            tool_name: tool_name.clone(),
                                        },
                                    },
                                    destination: None,
                                    timestamp: Utc::now(),
                                    raw_output: flag.raw_command.clone().unwrap_or_default(),
                                });
                            }
                        }

                        let seq_flags = BehavioralAnalyzer::analyze_sequence(
                            &recent_file_reads,
                            command,
                        );
                        for flag in &seq_flags {
                            det_events.push(DetonationEvent {
                                timestamp: Utc::now(),
                                event_type: DetonationEventType::NetworkActivity,
                                details: format!("🔴 SEQUENCE: {}", flag.description),
                                severity: flag.severity,
                            });

                            if flag.severity >= Severity::Critical {
                                exfil_events.push(ExfiltrationEvent {
                                    canary_id: uuid::Uuid::nil(),
                                    secret_type: crate::types::SecretType::GenericApiKey,
                                    channel: ExfilChannel::ToolCall {
                                        tool_name: "sequential_exfiltration".into(),
                                    },
                                    destination: None,
                                    timestamp: Utc::now(),
                                    raw_output: flag.raw_command.clone().unwrap_or_default(),
                                });
                            }
                        }
                    }

                    if tool_name == "read" {
                        if let Some(path) = args["path"].as_str() {
                            recent_file_reads.push(path.to_string());
                            if recent_file_reads.len() > 10 {
                                recent_file_reads.remove(0);
                            }
                        }
                    }

                    det_events.push(DetonationEvent {
                        timestamp: Utc::now(),
                        event_type: DetonationEventType::ToolCall,
                        details: format!(
                            "Tool call: {}({})",
                            tool_name,
                            args_str.chars().take(150).collect::<String>()
                        ),
                        severity: if detections.iter().any(|d| d.severity >= Severity::Critical) {
                            Severity::Critical
                        } else {
                            Severity::Info
                        },
                    });
                }
                PiEvent::ToolExecutionEnd {
                    tool_name,
                    result,
                    ..
                } => {
                    let result_str = serde_json::to_string(result).unwrap_or_default();
                    let detections = CanaryMonitor::check_text(&result_str, canaries);
                    for d in &detections {
                        det_events.push(DetonationEvent {
                            timestamp: Utc::now(),
                            event_type: DetonationEventType::FileAccess,
                            details: format!(
                                "LLM accessed canary-containing data via {}: {}",
                                tool_name,
                                d.secret_type.label()
                            ),
                            severity: Severity::Low,
                        });
                    }

                    det_events.push(DetonationEvent {
                        timestamp: Utc::now(),
                        event_type: DetonationEventType::ToolCall,
                        details: format!("Tool result from {}: {} bytes", tool_name, result_str.len()),
                        severity: Severity::Info,
                    });
                }
                PiEvent::TextOutput { content } => {
                    let detections = CanaryMonitor::check_text(content, canaries);
                    let (mut de, mut ee) = CanaryMonitor::detections_to_events(&detections);
                    det_events.append(&mut de);
                    exfil_events.append(&mut ee);

                    det_events.push(DetonationEvent {
                        timestamp: Utc::now(),
                        event_type: DetonationEventType::LlmResponse,
                        details: format!(
                            "LLM text output: {}",
                            content.chars().take(200).collect::<String>()
                        ),
                        severity: if detections.iter().any(|d| d.severity >= Severity::Critical) {
                            Severity::Critical
                        } else {
                            Severity::Info
                        },
                    });
                }
                PiEvent::Thinking { content } => {
                    det_events.push(DetonationEvent {
                        timestamp: Utc::now(),
                        event_type: DetonationEventType::LlmResponse,
                        details: format!(
                            "LLM thinking: {}",
                            content.chars().take(200).collect::<String>()
                        ),
                        severity: Severity::Info,
                    });
                }
            }
        }

        (det_events, exfil_events)
    }
}

// ---------------------------------------------------------------------------
// Pi JSONL event parser
// ---------------------------------------------------------------------------

/// Parse a single line from Pi's JSONL output into a PiEvent.
pub fn parse_pi_event(line: &str) -> Option<PiEvent> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;

    match v["type"].as_str()? {
        "toolcall_start" | "tool_call_start" => {
            let tool_name = v["name"]
                .as_str()
                .or_else(|| v["toolName"].as_str())
                .unwrap_or("unknown")
                .to_string();
            let tool_call_id = v["id"]
                .as_str()
                .or_else(|| v["toolCallId"].as_str())
                .unwrap_or("")
                .to_string();
            let args = v
                .get("arguments")
                .or_else(|| v.get("args"))
                .cloned()
                .unwrap_or(serde_json::Value::Null);

            Some(PiEvent::ToolCallStart {
                tool_call_id,
                tool_name,
                args,
            })
        }
        "tool_execution_end" | "tool_execution_result" => {
            let tool_name = v["toolName"].as_str().unwrap_or("unknown").to_string();
            let tool_call_id = v["toolCallId"].as_str().unwrap_or("").to_string();
            let result = v.get("result").cloned().unwrap_or(serde_json::Value::Null);

            Some(PiEvent::ToolExecutionEnd {
                tool_call_id,
                tool_name,
                result,
            })
        }
        "message_update" => {
            let event_type = v["assistantMessageEvent"]["type"].as_str().unwrap_or("");

            match event_type {
                "text_delta" | "text_start" => {
                    let content = v["assistantMessageEvent"]["delta"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    Some(PiEvent::TextOutput { content })
                }
                "thinking_delta" | "thinking_start" => {
                    let content = v["assistantMessageEvent"]["delta"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    Some(PiEvent::Thinking { content })
                }
                _ => None,
            }
        }
        "message_end" => {
            let message = &v["message"];
            if let Some(content) = message["content"].as_array() {
                for item in content {
                    if item["type"] == "text" {
                        if let Some(text) = item["text"].as_str() {
                            return Some(PiEvent::TextOutput {
                                content: text.to_string(),
                            });
                        }
                    }
                }
            }
            None
        }
        _ => None,
    }
}
