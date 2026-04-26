use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Pricing
// ---------------------------------------------------------------------------

/// How much each detonation type costs, in micro-USDC (6 decimals).
/// 1 USDC = 1,000,000 micro-USDC.
/// So 10,000 micro-USDC = $0.01
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pricing {
    /// Prompt injection test (document/data payload)
    pub prompt_injection_test: u64,
    /// Full sandbox with code execution
    pub code_execution: u64,
    /// Custom canary profiles, enterprise features
    pub enterprise: u64,
}

impl Default for Pricing {
    fn default() -> Self {
        Self {
            prompt_injection_test: 10_000,  // $0.01
            code_execution: 50_000,          // $0.05
            enterprise: 100_000,             // $0.10
        }
    }
}

// ---------------------------------------------------------------------------
// Payment Configuration
// ---------------------------------------------------------------------------

/// x402 payment configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentConfig {
    /// Ethereum address that receives USDC payments
    pub payment_address: String,
    /// Network name (e.g., "base")
    pub network: String,
    /// Chain ID (8453 = Base mainnet, 84532 = Base Sepolia)
    pub chain_id: u64,
    /// Pricing per detonation type
    pub pricing: Pricing,
    /// Facilitator URL for on-chain payment verification.
    /// Empty = self-verification (MVP, less secure).
    pub facilitator_url: String,
}

impl Default for PaymentConfig {
    fn default() -> Self {
        Self {
            payment_address: "0x0000000000000000000000000000000000000000".into(),
            network: "base".into(),
            chain_id: 8453,
            pricing: Pricing::default(),
            facilitator_url: String::new(),
        }
    }
}

impl PaymentConfig {
    pub fn from_env() -> Self {
        Self {
            payment_address: std::env::var("DAAS_PAYMENT_ADDRESS")
                .unwrap_or_else(|_| "0x0000000000000000000000000000000000000000".into()),
            network: std::env::var("DAAS_PAYMENT_NETWORK")
                .unwrap_or_else(|_| "base".into()),
            chain_id: std::env::var("DAAS_CHAIN_ID")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(8453),
            pricing: Pricing::default(),
            facilitator_url: std::env::var("DAAS_FACILITATOR_URL").unwrap_or_default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Payment State (prevents double-spending)
// ---------------------------------------------------------------------------

/// Tracks payment requests and their verification status.
pub struct PaymentStore {
    payments: RwLock<HashMap<String, PaymentRecord>>,
}

#[derive(Debug)]
struct PaymentRecord {
    detonation_id: Uuid,
    amount: u64,
    created_at: DateTime<Utc>,
    verified: bool,
    tx_hash: Option<String>,
}

impl PaymentStore {
    pub fn new() -> Self {
        Self {
            payments: RwLock::new(HashMap::new()),
        }
    }

    /// Create a new payment request (blocking, for use in sync contexts).
    pub fn try_create_blocking(&self, _amount: u64) -> Option<String> {
        // We need to create a payment ID. Since we can't access the async RwLock
        // in a sync context, we generate the ID here and insert it later.
        let payment_id = Uuid::new_v4().to_string();
        Some(payment_id)
    }

    /// Create a new payment request and return its ID.
    pub async fn create(&self, amount: u64) -> String {
        let payment_id = Uuid::new_v4().to_string();
        let record = PaymentRecord {
            detonation_id: Uuid::nil(),
            amount,
            created_at: Utc::now(),
            verified: false,
            tx_hash: None,
        };
        self.payments.write().await.insert(payment_id.clone(), record);
        payment_id
    }

    /// Link a payment to a specific detonation (after the detonation ID is known).
    pub async fn link_detonation(&self, payment_id: &str, detonation_id: Uuid) {
        if let Some(record) = self.payments.write().await.get_mut(payment_id) {
            record.detonation_id = detonation_id;
        }
    }

    /// Verify a payment proof and mark it as consumed.
    /// Returns Ok(()) if payment is valid, Err with reason if not.
    pub async fn verify(&self, payment_id: &str, tx_hash: &str) -> Result<PaymentVerified, PaymentError> {
        let mut payments = self.payments.write().await;

        let record = payments
            .get_mut(payment_id)
            .ok_or(PaymentError::UnknownPaymentId)?;

        if record.verified {
            tracing::warn!(payment_id = payment_id, "Double-spend attempt detected");
            return Err(PaymentError::AlreadyConsumed);
        }

        // In MVP mode: we accept any non-empty tx_hash.
        // In production:
        //   1. Verify the transaction exists on-chain (Base L2)
        //   2. Verify it sent the correct amount to our address
        //   3. Verify it hasn't been used before (double-spend protection)
        //   4. Optionally use a facilitator service for verification
        if tx_hash.is_empty() {
            return Err(PaymentError::InvalidProof);
        }

        record.verified = true;
        record.tx_hash = Some(tx_hash.into());

        tracing::info!(
            payment_id = payment_id,
            amount = record.amount,
            tx_hash = tx_hash,
            "Payment verified"
        );

        Ok(PaymentVerified {
            amount: record.amount,
            detonation_id: record.detonation_id,
        })
    }
}

#[derive(Debug)]
pub struct PaymentVerified {
    pub amount: u64,
    pub detonation_id: Uuid,
}

#[derive(Debug, thiserror::Error)]
pub enum PaymentError {
    #[error("Unknown payment ID")]
    UnknownPaymentId,
    #[error("Payment already consumed (double-spend)")]
    AlreadyConsumed,
    #[error("Invalid payment proof")]
    InvalidProof,
    #[error("Payment verification failed: {0}")]
    VerificationFailed(String),
}

// ---------------------------------------------------------------------------
// 402 Response Types
// ---------------------------------------------------------------------------

/// The response body for a 402 Payment Required response.
/// This tells the client exactly how to pay.
#[derive(Debug, Serialize, Deserialize)]
pub struct PaymentRequiredResponse {
    /// Unique payment request ID — include this when retrying
    pub payment_id: String,
    /// Amount to pay in micro-USDC
    pub amount: u64,
    /// Token to pay with
    pub token: String,
    /// Address to send payment to
    pub recipient: String,
    /// Network to pay on
    pub network: String,
    /// Chain ID
    pub chain_id: u64,
    /// Human-readable description
    pub description: String,
}

/// The request body when a client retries after payment.
/// They include their original request + the payment proof.
#[derive(Debug, Serialize, Deserialize)]
pub struct PaidDetonationRequest {
    /// The original detonation request
    #[serde(flatten)]
    pub request: crate::types::DetonationRequest,
    /// Payment ID from the 402 response
    pub payment_id: String,
    /// On-chain transaction hash proving payment
    pub payment_proof: String,
}

// ---------------------------------------------------------------------------
// Price Lookup
// ---------------------------------------------------------------------------

use crate::types::PayloadType;

/// Determine the price for a detonation based on payload type.
pub fn price_for_payload(payload_type: &PayloadType) -> u64 {
    let pricing = Pricing::default();
    match payload_type {
        PayloadType::Document | PayloadType::Data | PayloadType::Unknown => {
            pricing.prompt_injection_test
        }
        PayloadType::Code => pricing.code_execution,
    }
}