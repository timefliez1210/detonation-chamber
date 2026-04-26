use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    Json,
};
use serde::Serialize;
use uuid::Uuid;

use crate::orchestrator::DetonationEngine;
use crate::payment::{PaymentConfig, PaymentRequiredResponse, PaymentStore, price_for_payload};
use crate::types::{DetonationReport, DetonationRequest, DetonationStatus};

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AppState {
    pub engine: DetonationEngine,
    pub payment_config: PaymentConfig,
    pub payment_store: std::sync::Arc<PaymentStore>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub struct SubmitResponse {
    pub id: Uuid,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub id: Uuid,
    pub status: String,
    pub report: Option<DetonationReport>,
}

#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub payment_required: bool,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// POST /v1/detonate — Submit a payload for detonation.
///
/// x402 payment flow:
///   1. First request (no X-Payment headers) → 402 Payment Required
///   2. Client pays on-chain, includes proof → 202 Accepted
///
/// Set DAAS_PAYMENT_DISABLED=1 to skip payment (for testing).
pub async fn submit_detonation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DetonationRequest>,
) -> impl IntoResponse {
    // ── Check if payment is required ──────────────────────────────────
    let payment_disabled = std::env::var("DAAS_PAYMENT_DISABLED")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    if !payment_disabled {
        let payment_id = headers
            .get("X-Payment-Id")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let payment_proof = headers
            .get("X-Payment-Proof")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        // No payment proof → return 402
        if payment_id.is_none() || payment_proof.is_none() {
            return return_402(&state, &request);
        }

        // Verify payment
        let pid = payment_id.unwrap();
        let proof = payment_proof.unwrap();

        match state.payment_store.verify(&pid, &proof).await {
            Ok(_verified) => {
                tracing::info!(payment_id = pid, "Payment accepted");
            }
            Err(e) => {
                tracing::warn!(payment_id = pid, error = %e, "Payment verification failed");
                return (
                    StatusCode::PAYMENT_REQUIRED,
                    Json(ErrorResponse {
                        error: "payment_failed".into(),
                        message: format!("Payment verification failed: {}", e),
                    }),
                )
                    .into_response();
            }
        }
    }

    // ── Payment verified (or disabled) → create detonation ────────
    tracing::info!(
        payload_type = ?request.payload_type,
        llm_profile = ?request.llm_profile,
        "Processing detonation request"
    );

    let id = state.engine.submit(request).await;

    (
        StatusCode::ACCEPTED,
        Json(SubmitResponse {
            id,
            status: "queued".into(),
        }),
    )
        .into_response()
}

/// Build a 402 Payment Required response with x402 headers.
fn return_402(state: &AppState, request: &DetonationRequest) -> axum::response::Response {
    let amount = price_for_payload(&request.payload_type);
    let payment_id = match state.payment_store.try_create_blocking(amount) {
        Some(id) => id,
        None => {
            // Fallback: generate a UUID
            uuid::Uuid::new_v4().to_string()
        }
    };

    let response = PaymentRequiredResponse {
        payment_id: payment_id.clone(),
        amount,
        token: "USDC".into(),
        recipient: state.payment_config.payment_address.clone(),
        network: state.payment_config.network.clone(),
        chain_id: state.payment_config.chain_id,
        description: format!(
            "DaaS: {} analysis",
            match request.payload_type {
                crate::types::PayloadType::Document => "prompt injection",
                crate::types::PayloadType::Code => "code execution",
                _ => "payload",
            }
        ),
    };

    let mut headers = HeaderMap::new();
    headers.insert("X-Payment-Version", HeaderValue::from_static("1"));
    headers.insert(
        "X-Payment-Id",
        HeaderValue::from_str(&response.payment_id).unwrap(),
    );
    headers.insert(
        "X-Payment-Address",
        HeaderValue::from_str(&state.payment_config.payment_address).unwrap(),
    );
    headers.insert(
        "X-Payment-Amount",
        HeaderValue::from_str(&response.amount.to_string()).unwrap(),
    );
    headers.insert("X-Payment-Token", HeaderValue::from_static("USDC"));
    headers.insert(
        "X-Payment-Network",
        HeaderValue::from_str(&state.payment_config.network).unwrap(),
    );

    (StatusCode::PAYMENT_REQUIRED, headers, Json(response)).into_response()
}

/// GET /v1/detonate/:id — Check detonation status and retrieve report.
/// Free endpoint (you already paid for the detonation).
pub async fn get_detonation(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> impl IntoResponse {
    let detonation = state.engine.get(id).await;

    match detonation {
        Some(d) => {
            let status = match &d.status {
                DetonationStatus::Queued => "queued",
                DetonationStatus::Provisioning => "provisioning",
                DetonationStatus::Running => "running",
                DetonationStatus::Analyzing => "analyzing",
                DetonationStatus::Completed => "completed",
                DetonationStatus::Failed(ref e) => {
                    tracing::error!(error = %e, "Detonation failed");
                    "failed"
                }
            };

            Json(StatusResponse {
                id: d.id,
                status: status.into(),
                report: d.report,
            })
            .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse {
                error: "not_found".into(),
                message: "Detonation not found".into(),
            }),
        )
            .into_response(),
    }
}

/// GET /v1/health — Always free.
pub async fn health_check(State(_state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        payment_required: !std::env::var("DAAS_PAYMENT_DISABLED")
            .map(|v| v == "1" || v == "true")
            .unwrap_or(false),
    })
}