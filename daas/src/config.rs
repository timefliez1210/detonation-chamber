use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub server: ServerConfig,
    pub llm: LlmConfig,
    pub sandbox: SandboxConfig,
    #[serde(default)]
    pub traffic_review: TrafficReviewConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LlmConfig {
    /// Base URL for the OpenAI-compatible API
    /// (works with OpenAI, vLLM, Ollama, Together, etc.)
    pub api_base: String,

    /// API key (leave empty for local / no-auth endpoints)
    #[serde(default)]
    pub api_key: String,

    /// Default model to use when the client doesn't specify one
    pub default_model: String,

    /// Maximum tokens the LLM may generate per turn
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
}

fn default_max_tokens() -> u32 {
    1024
}

#[derive(Debug, Clone, Deserialize)]
pub struct TrafficReviewConfig {
    /// Whether to run LLM-based traffic review (Layer 3)
    #[serde(default = "default_traffic_review_enabled")]
    pub enabled: bool,

    /// Separate model for traffic review (defaults to llm.default_model)
    #[serde(default)]
    pub model: String,

    /// Separate max_tokens for the review prompt
    #[serde(default = "default_review_max_tokens")]
    pub max_tokens: u32,
}

fn default_traffic_review_enabled() -> bool {
    true
}

fn default_review_max_tokens() -> u32 {
    2048
}

impl Default for TrafficReviewConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            model: String::new(),
            max_tokens: 2048,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SandboxConfig {
    /// How many canary secrets to plant per detonation
    #[serde(default = "default_canary_count")]
    pub canary_count: usize,

    /// Maximum seconds a detonation may run before forced termination
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Path to Firecracker binary (empty = simulation mode)
    #[serde(default)]
    pub firecracker_bin: String,

    /// Path to VM image directory
    #[serde(default = "default_image_dir")]
    pub image_dir: String,
}

fn default_canary_count() -> usize {
    8
}

fn default_timeout_secs() -> u64 {
    120
}

fn default_image_dir() -> String {
    "./images".into()
}

impl Config {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}