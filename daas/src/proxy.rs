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
    /// Anthropic Messages upstream (for Claude Code), if configured.
    anthropic: Option<AnthropicUpstream>,
    /// Native Gemini Generative Language upstream, if configured.
    gemini: Option<GeminiUpstream>,
}

/// How the proxy authenticates Claude Code's `/v1/messages` traffic upstream.
#[derive(Clone, PartialEq, Eq)]
pub enum AnthropicAuth {
    /// A Console API key, sent as `x-api-key`.
    ApiKey(String),
    /// A Claude subscription token from `claude setup-token`, sent as a bearer
    /// token with the OAuth beta header.
    OAuth(String),
}

/// Never print credentials (this type ends up in Debug output and logs).
impl std::fmt::Debug for AnthropicAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnthropicAuth::ApiKey(_) => f.write_str("ApiKey(<redacted>)"),
            AnthropicAuth::OAuth(_) => f.write_str("OAuth(<redacted>)"),
        }
    }
}

#[derive(Clone)]
struct AnthropicUpstream {
    base: String,
    auth: AnthropicAuth,
}

#[derive(Clone)]
struct GeminiUpstream {
    base: String,
    api_key: String,
    model: String,
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
            anthropic: None,
            gemini: None,
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

    /// Start a proxy for native Gemini (`google-generative-ai`) requests:
    /// serves `POST /v1beta/models/*:{generateContent,streamGenerateContent}`,
    /// pins the upstream model, and injects the real `x-goog-api-key` header.
    pub async fn start_gemini(
        upstream_base: String,
        api_key: String,
        model: String,
    ) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("failed to bind LLM proxy: {}", e))?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let requests = Arc::new(AtomicU64::new(0));
        let state = ProxyState {
            http: reqwest::Client::new(),
            upstream_base: String::new(),
            api_key: String::new(),
            model: String::new(),
            extra_body: None,
            requests: requests.clone(),
            anthropic: None,
            gemini: Some(GeminiUpstream {
                base: normalize_gemini_native_base(&upstream_base),
                api_key,
                model,
            }),
        };
        let app = Router::new().fallback(handle).with_state(state);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                warn!(error = %e, "LLM proxy stopped");
            }
        });
        info!(port, "Gemini proxy started");
        Ok(Self { port, requests })
    }

    /// Start a proxy for Claude Code: serves the Anthropic Messages API
    /// (`/v1/messages*`) and adds the real credential upstream. The sandboxed
    /// Claude Code only ever sees a placeholder API key.
    pub async fn start_anthropic(auth: AnthropicAuth) -> Result<Self, String> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| format!("failed to bind LLM proxy: {}", e))?;
        let port = listener.local_addr().map_err(|e| e.to_string())?.port();
        let requests = Arc::new(AtomicU64::new(0));
        let state = ProxyState {
            http: reqwest::Client::new(),
            upstream_base: String::new(),
            api_key: String::new(),
            model: String::new(),
            extra_body: None,
            requests: requests.clone(),
            anthropic: Some(AnthropicUpstream {
                base: std::env::var("DAAS_ANTHROPIC_API_BASE")
                    .unwrap_or_else(|_| "https://api.anthropic.com".into()),
                auth,
            }),
            gemini: None,
        };
        let app = Router::new().fallback(handle).with_state(state);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                warn!(error = %e, "LLM proxy stopped");
            }
        });
        info!(port, "Anthropic proxy started");
        Ok(Self { port, requests })
    }

    /// Base URL for an Anthropic-protocol client (`ANTHROPIC_BASE_URL`).
    pub fn anthropic_base_url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    /// Base URL for a native Gemini client (`google-generative-ai`).
    pub fn gemini_base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1beta", self.port)
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
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(up) = st.anthropic.clone() {
        return handle_anthropic(&st, &up, method, uri, headers, body).await;
    }
    if let Some(up) = st.gemini.clone() {
        return handle_gemini(&st, &up, method, uri, headers, body).await;
    }
    if method != Method::POST || !uri.path().ends_with("/chat/completions") {
        return error(
            StatusCode::NOT_FOUND,
            "only POST /v1/chat/completions is proxied",
        );
    }

    let json =
        match prepare_openai_body(&body, &st.model, st.extra_body.as_ref(), &st.upstream_base) {
            Ok(v) => v,
            Err(e) => return error(StatusCode::BAD_REQUEST, &format!("invalid JSON: {}", e)),
        };

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

/// Forward Claude Code's Anthropic Messages requests, swapping in the real
/// credential. Only `/v1/messages` and `/v1/messages/count_tokens` pass.
async fn handle_anthropic(
    st: &ProxyState,
    up: &AnthropicUpstream,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path();
    if method != Method::POST || !(path == "/v1/messages" || path == "/v1/messages/count_tokens") {
        return error(StatusCode::NOT_FOUND, "only POST /v1/messages is proxied");
    }
    let target = format!(
        "{}{}",
        up.base.trim_end_matches('/'),
        uri.path_and_query().map(|p| p.as_str()).unwrap_or(path)
    );
    let mut req = st.http.post(target).body(body);
    // Pass Claude Code's own headers through, except credentials and
    // hop-by-hop headers.
    let mut betas: Vec<String> = Vec::new();
    for (name, value) in headers.iter() {
        let n = name.as_str().to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "host"
                | "authorization"
                | "x-api-key"
                | "content-length"
                | "connection"
                | "accept-encoding"
        ) {
            continue;
        }
        if n == "anthropic-beta" {
            if let Ok(v) = value.to_str() {
                betas.extend(
                    v.split(',')
                        .map(|b| b.trim().to_string())
                        .filter(|b| !b.is_empty()),
                );
            }
            continue;
        }
        req = req.header(name, value);
    }
    match &up.auth {
        AnthropicAuth::ApiKey(k) => {
            req = req.header("x-api-key", k);
        }
        AnthropicAuth::OAuth(t) => {
            req = req.bearer_auth(t);
            if !betas.iter().any(|b| b == "oauth-2025-04-20") {
                betas.push("oauth-2025-04-20".into());
            }
        }
    }
    if !betas.is_empty() {
        req = req.header("anthropic-beta", betas.join(","));
    }
    st.requests.fetch_add(1, Ordering::Relaxed);
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

/// Forward native Gemini (`google-generative-ai`) requests, pinning the model
/// segment and swapping in the real `x-goog-api-key` header.
async fn handle_gemini(
    st: &ProxyState,
    up: &GeminiUpstream,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(action) = (method == Method::POST)
        .then(|| gemini_action(uri.path()))
        .flatten()
    else {
        return error(
            StatusCode::NOT_FOUND,
            "only POST /v1beta/models/*:{generateContent,streamGenerateContent} is proxied",
        );
    };

    let target = build_gemini_upstream_url(&up.base, &up.model, action, uri.query());
    let mut req = st.http.post(target).body(body);
    for (name, value) in headers.iter() {
        let n = name.as_str().to_ascii_lowercase();
        if matches!(
            n.as_str(),
            "host"
                | "authorization"
                | "x-goog-api-key"
                | "content-length"
                | "connection"
                | "accept-encoding"
        ) {
            continue;
        }
        req = req.header(name, value);
    }
    if !up.api_key.is_empty() {
        req = req.header("x-goog-api-key", &up.api_key);
    }

    st.requests.fetch_add(1, Ordering::Relaxed);
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

/// Returns true if `url` points at Google's Generative Language API host.
pub fn is_gemini_host(url: &str) -> bool {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .is_some_and(|h| h == "generativelanguage.googleapis.com")
}

/// Convert either the OpenAI-compat Gemini base (`.../v1beta/openai`) or native
/// base (`.../v1beta` / `https://generativelanguage.googleapis.com`) to the
/// native versioned base URL (`.../v1beta`).
fn normalize_gemini_native_base(base: &str) -> String {
    let trimmed = base.trim_end_matches('/');
    let without_openai = trimmed.strip_suffix("/openai").unwrap_or(trimmed);
    if without_openai.ends_with("/v1beta") || without_openai.ends_with("/v1") {
        without_openai.to_string()
    } else {
        format!("{}/v1beta", without_openai)
    }
}

/// Extract the allowed Gemini generation action from a request path.
fn gemini_action(path: &str) -> Option<&'static str> {
    let rest = path
        .strip_prefix("/v1beta/models/")
        .or_else(|| path.strip_prefix("/v1/models/"))
        .or_else(|| path.strip_prefix("/models/"))?;
    let (model, action) = rest.split_once(':')?;
    if model.is_empty() || model.contains('/') {
        return None;
    }
    match action {
        "generateContent" => Some("generateContent"),
        "streamGenerateContent" => Some("streamGenerateContent"),
        _ => None,
    }
}

/// Build the pinned upstream Gemini URL, preserving safe query parameters (such
/// as `alt=sse`) while stripping any client-supplied `key` parameter.
fn build_gemini_upstream_url(base: &str, model: &str, action: &str, query: Option<&str>) -> String {
    let clean_model = model.strip_prefix("models/").unwrap_or(model);
    let mut target = format!(
        "{}/models/{}:{}",
        base.trim_end_matches('/'),
        clean_model,
        action
    );
    if let Some(q) = query {
        let mut ser = url::form_urlencoded::Serializer::new(String::new());
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            if !k.eq_ignore_ascii_case("key") {
                ser.append_pair(&k, &v);
            }
        }
        let filtered = ser.finish();
        if !filtered.is_empty() {
            target.push('?');
            target.push_str(&filtered);
        }
    }
    target
}

/// Parse and normalize an OpenAI-compatible chat completions request body:
/// pin `model`, merge configured `extra_body` defaults, and strip fields
/// rejected by Gemini's OpenAI-compatible endpoint (such as `store`).
fn prepare_openai_body(
    body: &[u8],
    model: &str,
    extra_body: Option<&serde_json::Value>,
    upstream_base: &str,
) -> Result<serde_json::Value, serde_json::Error> {
    let mut json: serde_json::Value = serde_json::from_slice(body)?;
    if let Some(obj) = json.as_object_mut() {
        obj.insert("model".into(), serde_json::Value::String(model.to_string()));
        if let Some(extra) = extra_body.and_then(|e| e.as_object()) {
            for (k, v) in extra {
                obj.entry(k.clone()).or_insert_with(|| v.clone());
            }
        }
        if is_gemini_host(upstream_base) {
            obj.remove("store");
        }
    }
    Ok(json)
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

#[cfg(test)]
mod tests {
    use super::{
        build_gemini_upstream_url, gemini_action, is_gemini_host, normalize_gemini_native_base,
        prepare_openai_body, AnthropicAuth,
    };

    #[test]
    fn auth_debug_never_prints_secret() {
        let s = format!("{:?}", AnthropicAuth::OAuth("sk-ant-oat01-secret".into()));
        assert!(!s.contains("secret"), "{}", s);
    }

    #[test]
    fn gemini_endpoint_check_uses_exact_host() {
        assert!(is_gemini_host(
            "https://generativelanguage.googleapis.com/v1beta/openai"
        ));
        assert!(is_gemini_host(
            "https://generativelanguage.googleapis.com/v1beta"
        ));
        assert!(!is_gemini_host(
            "https://evil.example/generativelanguage.googleapis.com"
        ));
        assert!(!is_gemini_host("https://api.openai.com/v1"));
    }

    #[test]
    fn normalize_gemini_base_strips_openai_suffix() {
        assert_eq!(
            normalize_gemini_native_base("https://generativelanguage.googleapis.com/v1beta/openai"),
            "https://generativelanguage.googleapis.com/v1beta"
        );
        assert_eq!(
            normalize_gemini_native_base(
                "https://generativelanguage.googleapis.com/v1beta/openai/"
            ),
            "https://generativelanguage.googleapis.com/v1beta"
        );
        assert_eq!(
            normalize_gemini_native_base("https://generativelanguage.googleapis.com"),
            "https://generativelanguage.googleapis.com/v1beta"
        );
    }

    #[test]
    fn gemini_action_validates_path_and_blocks_other_endpoints() {
        assert_eq!(
            gemini_action("/v1beta/models/gemini-3.8-flash:streamGenerateContent"),
            Some("streamGenerateContent")
        );
        assert_eq!(
            gemini_action("/v1beta/models/gemini-4-neon:generateContent"),
            Some("generateContent")
        );
        assert_eq!(gemini_action("/v1beta/models"), None);
        assert_eq!(
            gemini_action("/v1beta/models/foo/bar:generateContent"),
            None
        );
        assert_eq!(gemini_action("/v1beta/files"), None);
    }

    #[test]
    fn gemini_upstream_url_pins_model_and_strips_client_key() {
        let url = build_gemini_upstream_url(
            "https://generativelanguage.googleapis.com/v1beta",
            "gemini-4-neon",
            "streamGenerateContent",
            Some("alt=sse&key=placeholder"),
        );
        assert_eq!(
            url,
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-4-neon:streamGenerateContent?alt=sse"
        );
    }

    #[test]
    fn prepare_body_strips_store_for_gemini_only() {
        let raw = br#"{"model":"target","store":false,"messages":[]}"#;
        let gemini = prepare_openai_body(
            raw,
            "gemini-3.8-flash",
            None,
            "https://generativelanguage.googleapis.com/v1beta/openai",
        )
        .expect("valid JSON");
        assert_eq!(gemini["model"], "gemini-3.8-flash");
        assert!(
            gemini.get("store").is_none(),
            "Gemini OpenAI endpoint rejects `store`: {gemini}"
        );

        let openai = prepare_openai_body(raw, "gpt-4o-mini", None, "https://api.openai.com/v1")
            .expect("valid JSON");
        assert_eq!(openai["model"], "gpt-4o-mini");
        assert_eq!(openai["store"], false);
    }
}
