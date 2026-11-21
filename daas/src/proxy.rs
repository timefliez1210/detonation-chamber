//! Credential-isolating LLM proxy.
//!
//! The detonation agent must be able to call an LLM, but it must never be able
//! to read the operator's real API key (it has a bash tool and is, by design,
//! following attacker instructions). Pi inside the sandbox is configured with a
//! placeholder key and points at this proxy on 127.0.0.1. The proxy:
//!
//! * only accepts `POST …/chat/completions`
//! * forces the `model` field to the configured upstream model
//! * adds the real `Authorization` header and forwards to the upstream base URL
//! * streams the response back unchanged

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::State;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::Response;
use axum::Router;
use futures_util::TryStreamExt;
use tracing::{info, warn};

#[derive(Clone)]
struct ProxyState {
    http: reqwest::Client,
    upstream_base: String,
    api_key: String,
    model: String,
    extra_body: Option<serde_json::Value>,
    requests: Arc<AtomicU64>,
}

/// A running proxy. Dropping it does not stop the server; it lives for the
/// remainder of the process (one detonation per CLI invocation).
pub struct LlmProxy {
    pub port: u16,
    requests: Arc<AtomicU64>,
}

impl LlmProxy {
    /// Start the proxy on a random 127.0.0.1 port.
    pub async fn start(
        upstream_base: String,
        api_key: String,
        model: String,
        extra_body: Option<serde_json::Value>,
    ) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("failed to bind LLM proxy: {}", e))?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let requests = Arc::new(AtomicU64::new(0));

        let state = ProxyState {
            http: reqwest::Client::new(),
            upstream_base: upstream_base.trim_end_matches('/').to_string(),
            api_key,
            model,
            extra_body,
            requests: requests.clone(),
        };

        let app = Router::new().fallback(handle).with_state(state);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                warn!(error = %e, "LLM proxy stopped");
            }
        });

        info!(port, "LLM proxy started");
        Ok(Self { port, requests })
    }

    /// Base URL to give to the sandboxed agent (OpenAI-compatible).
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port)
    }

    /// Number of upstream requests forwarded so far.
    pub fn request_count(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
}

async fn handle(
    State(st): State<ProxyState>,
    method: Method,
    uri: Uri,
    _headers: HeaderMap,
    body: Bytes,
) -> Response {
    if method != Method::POST || !uri.path().ends_with("/chat/completions") {
        return error(
            StatusCode::NOT_FOUND,
            "only POST /v1/chat/completions is proxied",
        );
    }

    let mut json: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => return error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {}", e)),
    };
    json["model"] = serde_json::Value::String(st.model.clone());
    if let (Some(extra), Some(obj)) = (
        st.extra_body.as_ref().and_then(|e| e.as_object()),
        json.as_object_mut(),
    ) {
        for (k, v) in extra {
            obj.entry(k.clone()).or_insert_with(|| v.clone());
        }
    }

    st.requests.fetch_add(1, Ordering::Relaxed);
    let mut req = st
        .http
        .post(format!("{}/chat/completions", st.upstream_base))
        .header("content-type", "application/json")
        .header("X-Title", "detonation-chamber")
        .json(&json);
    if !st.api_key.is_empty() {
        req = req.bearer_auth(&st.api_key);
    }

    let upstream = match req.send().await {
        Ok(r) => r,
        Err(e) => {
            return error(
                StatusCode::BAD_GATEWAY,
                &format!("upstream request failed: {}", e),
            )
        }
    };

    let status =
        StatusCode::from_u16(upstream.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let content_type = upstream
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json")
        .to_string();
    let stream = upstream.bytes_stream().map_err(std::io::Error::other);

    Response::builder()
        .status(status)
        .header("content-type", content_type)
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| error(StatusCode::INTERNAL_SERVER_ERROR, "response build failed"))
}

fn error(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({"error": {"message": msg}}).to_string(),
        ))
        .unwrap()
}
