use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Client request
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetonationRequest {
    /// The untrusted payload to test (text, code, document content, etc.)
    pub payload: String,

    /// What kind of payload is this?
    #[serde(default)]
    pub payload_type: PayloadType,

    /// Which LLM model/persona should the sandbox simulate?
    #[serde(default)]
    pub llm_profile: LlmProfile,

    /// For code-execution mode: which runtime to use
    pub runtime: Option<RuntimeType>,

    /// Optional webhook to POST the final report to
    pub callback_url: Option<String>,

    /// Maximum conversation turns the LLM may take inside the sandbox
    #[serde(default = "default_max_turns")]
    pub max_turns: usize,
}

fn default_max_turns() -> usize {
    10
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PayloadType {
    #[default]
    Document,
    Code,
    Data,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum LlmProfile {
    #[default]
    Gpt4,
    Claude,
    Llama3,
    Local {
        model_name: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeType {
    Python,
    Node,
    Shell,
    Binary,
}

// ---------------------------------------------------------------------------
// Detonation state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Detonation {
    pub id: Uuid,
    pub status: DetonationStatus,
    pub request: DetonationRequest,
    pub canaries: Vec<Canary>,
    pub events: Vec<DetonationEvent>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub report: Option<DetonationReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DetonationStatus {
    Queued,
    Provisioning,
    Running,
    Analyzing,
    Completed,
    Failed(String),
}

// ---------------------------------------------------------------------------
// Canaries (honeypot secrets)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Canary {
    pub id: Uuid,
    pub secret_type: SecretType,
    pub value: String,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum SecretType {
    AwsAccessKey,
    AwsSecretKey,
    StripeKey,
    GithubPat,
    DatabaseUrl,
    EthWallet,
    SshPrivateKey,
    SlackWebhook,
    GenericApiKey,
}

impl SecretType {
    pub fn label(&self) -> &str {
        match self {
            Self::AwsAccessKey => "AWS Access Key ID",
            Self::AwsSecretKey => "AWS Secret Access Key",
            Self::StripeKey => "Stripe Secret Key",
            Self::GithubPat => "GitHub Personal Access Token",
            Self::DatabaseUrl => "Database Connection URL",
            Self::EthWallet => "Ethereum Wallet Private Key",
            Self::SshPrivateKey => "SSH Private Key",
            Self::SlackWebhook => "Slack Webhook URL",
            Self::GenericApiKey => "API Key",
        }
    }
}

// ---------------------------------------------------------------------------
// Events emitted during detonation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetonationEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: DetonationEventType,
    pub details: String,
    pub severity: Severity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DetonationEventType {
    LlmResponse,
    ToolCall,
    CanaryDetected,
    FileAccess,
    NetworkActivity,
    ProcessSpawn,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

// ---------------------------------------------------------------------------
// Exfiltration detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExfiltrationEvent {
    pub canary_id: Uuid,
    pub secret_type: SecretType,
    pub channel: ExfilChannel,
    pub destination: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub raw_output: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExfilChannel {
    /// Canary appeared directly in the LLM's text output
    DirectOutput,
    /// Canary appeared inside a tool-call argument (e.g. send_email body)
    ToolCall { tool_name: String },
    /// Canary appeared in an outbound HTTP request
    NetworkRequest { url: String },
    /// Canary appeared in an outbound email
    Email { to: String },
}

// ---------------------------------------------------------------------------
// Final report
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetonationReport {
    pub verdict: Verdict,
    pub confidence: f32,
    pub exfiltration_events: Vec<ExfiltrationEvent>,
    pub behavioral_timeline: Vec<BehavioralEntry>,
    pub payload_analysis: String,
    /// Run details and the signals behind the verdict (Pi detonations only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ReportMetadata>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ReportMetadata {
    pub provider: String,
    pub model: String,
    pub isolation: String,
    pub framing: String,
    #[serde(default)]
    pub persona: String,
    pub turns: usize,
    pub tool_calls: usize,
    pub terminated_reason: String,
    pub duration_secs: f64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    /// Human-readable reasons for the verdict, strongest first.
    pub signals: Vec<String>,
    pub secrets_accessed: Vec<String>,
    pub behavioral_flags: Vec<FlagSummary>,
    pub network_canary_hits: usize,
    pub unexpected_traffic: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_review: Option<String>,
    /// Layer 6: the agent's own judgement of the content, if reviewed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_alarm: Option<crate::agent_review::AgentAlarm>,
    /// The exact user prompt the agent received (for eval verification).
    #[serde(default)]
    pub prompt: String,
    /// The agent's full final answer.
    #[serde(default)]
    pub final_output: String,
    /// The agent's reasoning/thinking blocks, concatenated (capped).
    #[serde(default)]
    pub reasoning: String,
    /// Every tool call with full arguments and (capped) result text.
    #[serde(default)]
    pub tool_calls_full: Vec<ToolCallRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolCallRecord {
    pub id: String,
    pub tool: String,
    /// Arguments as JSON text.
    pub args: String,
    pub result: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlagSummary {
    pub flag: String,
    pub severity: Severity,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Safe,
    Suspicious,
    Malicious,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehavioralEntry {
    pub timestamp: DateTime<Utc>,
    pub description: String,
    pub severity: Severity,
}
