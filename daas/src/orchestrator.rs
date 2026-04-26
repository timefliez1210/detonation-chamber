use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error, warn, instrument};
use uuid::Uuid;

use crate::behavioral::NetworkCanary;
use crate::config::Config;
use crate::llm::LlmClient;
use crate::pi_agent::PiAgent;
use crate::report::ReportBuilder;
use crate::traffic::TrafficCapture;
use crate::types::{
    Detonation, DetonationRequest, DetonationStatus,
};

pub type DetonationStore = Arc<RwLock<HashMap<Uuid, Detonation>>>;

/// The detonation engine orchestrates the full lifecycle.
/// Supports two modes:
///   - "pi" mode: Uses Pi as the agent (real tools, real filesystem access)
///   - "llm" mode: Uses direct LLM API with simulated tools (legacy)
#[derive(Clone)]
pub struct DetonationEngine {
    store: DetonationStore,
    config: Arc<Config>,
}

impl DetonationEngine {
    pub fn new(store: DetonationStore, config: Arc<Config>) -> Self {
        Self { store, config }
    }

    /// Queue a new detonation and kick off the async execution.
    #[instrument(skip(self, request))]
    pub async fn submit(&self, request: DetonationRequest) -> Uuid {
        let id = Uuid::new_v4();

        let detonation = Detonation {
            id,
            status: DetonationStatus::Queued,
            request,
            canaries: Vec::new(),
            events: Vec::new(),
            started_at: Utc::now(),
            completed_at: None,
            report: None,
        };

        {
            let mut store = self.store.write().await;
            store.insert(id, detonation);
        }

        let pi_bin = std::env::var("PI_BIN").unwrap_or_else(|_| "pi".into());
        let mode = if which_exists(&pi_bin) {
            "pi"
        } else {
            "llm"
        };

        info!(detonation_id = %id, mode = mode, "Starting detonation");

        let store = self.store.clone();
        let config = self.config.clone();

        tokio::spawn(async move {
            let result = match mode {
                "pi" => run_pi_detonation(id, store.clone(), &config).await,
                _ => run_llm_detonation(id, store.clone(), &config).await,
            };

            if let Err(e) = result {
                error!(detonation_id = %id, error = %e, "Detonation failed");

                let mut store = store.write().await;
                if let Some(d) = store.get_mut(&id) {
                    d.status = DetonationStatus::Failed(e.to_string());
                    d.completed_at = Some(Utc::now());
                }
            }
        });

        id
    }

    pub async fn get(&self, id: Uuid) -> Option<Detonation> {
        let store = self.store.read().await;
        store.get(&id).cloned()
    }
}

fn which_exists(bin: &str) -> bool {
    which::which(bin).ok().is_some()
}

// ---------------------------------------------------------------------------
// Pi-based detonation with full stack
// ---------------------------------------------------------------------------

async fn run_pi_detonation(
    id: Uuid,
    store: DetonationStore,
    config: &Config,
) -> Result<(), String> {
    info!(detonation_id = %id, "Running Pi-based detonation");
    update_status(&store, id, DetonationStatus::Provisioning).await;

    let request = {
        let store = store.read().await;
        store
            .get(&id)
            .map(|d| d.request.clone())
            .ok_or("Detonation not found")?
    };

    // ── Create Pi agent ────────────────────────────────────────────────
    let pi_bin = std::env::var("PI_BIN").unwrap_or_else(|_| "pi".into());
    let provider =
        std::env::var("DAAS_LLM_PROVIDER").unwrap_or_else(|_| "ollama".into());
    let model = config.llm.default_model.clone();
    let api_key = config.llm.api_key.clone();

    // ── Layer 1: TrafficCapture for bash command network extraction ────
    let traffic_capture = TrafficCapture::new(config.llm.api_base.clone());

    // ── Layer 2: NetworkCanary HTTP server planted in honeypot ────────
    let network_canary = match NetworkCanary::start().await {
        Ok(nc) => {
            info!(
                url = %nc.url,
                port = nc.port,
                "Network canary server started for detonation"
            );
            Some(Arc::new(nc))
        }
        Err(e) => {
            warn!(error = %e, "Failed to start network canary server, continuing without it");
            None
        }
    };

    // ── Layer 3: TrafficReviewer (LLM-based traffic review) ───────────
    let review_model = if config.traffic_review.model.is_empty() {
        config.llm.default_model.clone()
    } else {
        config.traffic_review.model.clone()
    };
    let review_client = LlmClient::new(
        config.llm.api_base.clone(),
        config.llm.api_key.clone(),
        review_model,
        config.traffic_review.max_tokens,
    );

    // ── Build the agent with all layers ────────────────────────────────
    let mut agent = PiAgent::new(pi_bin, provider, model, api_key)
        .with_max_turns(request.max_turns)
        .with_timeout(config.sandbox.timeout_secs)
        .with_traffic_capture(traffic_capture)
        .with_review_client(review_client)
        .with_traffic_review_enabled(config.traffic_review.enabled);

    if let Some(nc) = &network_canary {
        agent = agent.with_network_canary(nc.clone());
    }

    update_status(&store, id, DetonationStatus::Running).await;

    // ── Execute the detonation ─────────────────────────────────────────
    let result = agent.detonate(&request.payload, config.sandbox.canary_count).await;

    // ── Store canaries ─────────────────────────────────────────────────
    {
        let mut store = store.write().await;
        if let Some(d) = store.get_mut(&id) {
            d.canaries = result.canaries.clone();
        }
    }

    // ── Generate report using the unified builder that considers all layers ──
    update_status(&store, id, DetonationStatus::Analyzing).await;

    let report = crate::report::ReportBuilder::from_pi_result(&result);

    info!(
        detonation_id = %id,
        verdict = ?report.verdict,
        confidence = report.confidence,
        exfil_count = report.exfiltration_events.len(),
        has_traffic_review = result.traffic_review.is_some(),
        network_canary_hits = result.network_canary_hits.len(),
        "Pi detonation complete"
    );

    // ── Update final state ────────────────────────────────────────────
    {
        let mut store = store.write().await;
        if let Some(d) = store.get_mut(&id) {
            d.events = result.events;
            d.report = Some(report);
            d.completed_at = Some(Utc::now());
            d.status = DetonationStatus::Completed;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy LLM-based detonation (simulated tools)
// ---------------------------------------------------------------------------

async fn run_llm_detonation(
    id: Uuid,
    store: DetonationStore,
    config: &Config,
) -> Result<(), String> {
    use crate::agent::Agent;
    use crate::canary::CanaryGenerator;
    use crate::honeypot::HoneypotBuilder;
    use crate::llm::LlmClient;

    info!(detonation_id = %id, "Running LLM-based detonation (legacy mode)");
    update_status(&store, id, DetonationStatus::Provisioning).await;

    let canaries = CanaryGenerator::generate(config.sandbox.canary_count);

    {
        let mut store = store.write().await;
        if let Some(d) = store.get_mut(&id) {
            d.canaries = canaries.clone();
        }
    }

    let environment = HoneypotBuilder::build(&canaries);

    let request = {
        let store = store.read().await;
        store
            .get(&id)
            .map(|d| d.request.clone())
            .ok_or("Detonation not found")?
    };

    update_status(&store, id, DetonationStatus::Running).await;

    let llm_client = LlmClient::new(
        config.llm.api_base.clone(),
        config.llm.api_key.clone(),
        config.llm.default_model.clone(),
        config.llm.max_tokens,
    );

    let mut agent = Agent::new(llm_client, environment, canaries.clone(), request.max_turns);

    let result = agent.run(&request.payload).await;

    update_status(&store, id, DetonationStatus::Analyzing).await;

    let report = ReportBuilder::build(&result);

    {
        let mut store = store.write().await;
        if let Some(d) = store.get_mut(&id) {
            d.events = result.events;
            d.report = Some(report);
            d.completed_at = Some(Utc::now());
            d.status = DetonationStatus::Completed;
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn update_status(store: &DetonationStore, id: Uuid, status: DetonationStatus) {
    let mut store = store.write().await;
    if let Some(d) = store.get_mut(&id) {
        d.status = status;
    }
}
