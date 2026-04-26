mod agent;
mod api;
mod behavioral;
mod canary;
mod config;
mod firecracker;
mod honeypot;
mod llm;
mod monitor;
mod orchestrator;
mod payment;
mod pi_agent;
mod report;
mod tools;
mod traffic;
mod types;

#[cfg(test)]
mod tests_e2e;

use std::collections::HashMap;
use std::sync::Arc;

use axum::routing::{get, post};
use axum::Router;
use tokio::sync::RwLock;
use tower_http::cors::CorsLayer;
use tracing_subscriber::EnvFilter;

use api::AppState;
use config::Config;
use orchestrator::{DetonationEngine, DetonationStore};
use payment::{PaymentConfig, PaymentStore};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ── Load .env file if present ────────────────────────────────────────
    let _ = dotenvy::dotenv();

    // ── Logging ────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("daas=info,tower_http=info")),
        )
        .init();

    // ── Configuration ─────────────────────────────────────────────────
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".into());

    let config = Config::load(&config_path).unwrap_or_else(|e| {
        tracing::warn!("Failed to load config from {}: {}. Using defaults + env vars.", config_path, e);
        Config {
            server: config::ServerConfig {
                host: "0.0.0.0".into(),
                port: 8080,
            },
            llm: config::LlmConfig {
                api_base: std::env::var("DAAS_LLM_API_BASE")
                    .unwrap_or_else(|_| "https://api.openai.com/v1".into()),
                api_key: std::env::var("DAAS_LLM_API_KEY")
                    .or_else(|_| std::env::var("OLLAMA_API"))
                    .unwrap_or_default(),
                default_model: std::env::var("DAAS_LLM_MODEL")
                    .unwrap_or_else(|_| "gpt-4o".into()),
                max_tokens: 1024,
            },
            sandbox: config::SandboxConfig {
                canary_count: 8,
                timeout_secs: 120,
                firecracker_bin: String::new(),
                image_dir: "./images".into(),
            },
            traffic_review: config::TrafficReviewConfig::default(),
        }
    });

    // Allow env var overrides (highest priority)
    let mut config = config;
    if let Ok(key) = std::env::var("DAAS_LLM_API_KEY") {
        config.llm.api_key = key;
    }
    if let Ok(key) = std::env::var("OLLAMA_API") {
        // OLLAMA_API takes second priority; only used if DAAS_LLM_API_KEY not set
        if config.llm.api_key.is_empty() {
            config.llm.api_key = key;
        }
    }
    if let Ok(base) = std::env::var("DAAS_LLM_API_BASE") {
        config.llm.api_base = base;
    }
    if let Ok(model) = std::env::var("DAAS_LLM_MODEL") {
        config.llm.default_model = model;
    }
    // If using Ollama locally, override the base URL
    if config.llm.api_base.contains("openai.com") && config.llm.api_key.contains(".") {
        // Looks like a custom API key, not OpenAI — check if we should use Ollama
        // Auto-detect local Ollama
        if let Ok(_) = reqwest::get("http://localhost:11434/api/tags").await {
            tracing::info!("Detected local Ollama, switching API base");
            config.llm.api_base = "http://localhost:11434/v1".into();
            if config.llm.default_model == "gpt-4o" {
                config.llm.default_model = "llama3".into();
            }
        }
    }

    let config = Arc::new(config);

    // ── Payment configuration (x402) ──────────────────────────────────
    let payment_config = PaymentConfig::from_env();
    let payment_store = Arc::new(PaymentStore::new());

    tracing::info!(
        address = %payment_config.payment_address,
        network = %payment_config.network,
        chain_id = payment_config.chain_id,
        "x402 payment configured"
    );

    // ── Shared state ──────────────────────────────────────────────────
    let store: DetonationStore = Arc::new(RwLock::new(HashMap::new()));
    let engine = DetonationEngine::new(store, config.clone());

    let app_state = AppState {
        engine,
        payment_config: payment_config.clone(),
        payment_store,
    };

    // ── HTTP server ───────────────────────────────────────────────────
    let app = Router::new()
        .route("/v1/detonate", post(api::submit_detonation))
        .route("/v1/detonate/{id}", get(api::get_detonation))
        .route("/v1/health", get(api::health_check))
        .layer(CorsLayer::permissive())
        .with_state(app_state);

    let addr = format!("{}:{}", config.server.host, config.server.port);
    tracing::info!("🧨 DaaS server starting on {}", addr);
    tracing::info!(
        api_base = %config.llm.api_base,
        model = %config.llm.default_model,
        "LLM configuration"
    );
    tracing::info!("Submit payloads: POST http://{}/v1/detonate", addr);
    tracing::info!("Health check:     GET  http://{}/v1/health", addr);

    let payment_disabled = std::env::var("DAAS_PAYMENT_DISABLED")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    if payment_disabled {
        tracing::warn!("⚠️  Payment requirement DISABLED (DAAS_PAYMENT_DISABLED=1)");
    } else {
        tracing::info!("💰 Payment required: x402 protocol enabled");
        tracing::info!(
            "   Send USDC {} to {} on {}",
            payment_config.pricing.prompt_injection_test as f64 / 1_000_000.0,
            payment_config.payment_address,
            payment_config.network,
        );
    }

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}