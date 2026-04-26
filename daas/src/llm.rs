use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LlmError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("API error: {status} {body}")]
    Api { status: u16, body: String },
    #[error("Failed to parse LLM response: {0}")]
    Parse(#[from] serde_json::Error),
    #[error("No response from LLM")]
    EmptyResponse,
}

/// A single message in the conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "lowercase")]
pub enum LlmMessage {
    System {
        content: String,
    },
    User {
        content: String,
    },
    Assistant {
        content: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        tool_calls: Option<Vec<LlmToolCall>>,
    },
    #[serde(rename = "tool")]
    ToolResult {
        #[serde(rename = "tool_call_id")]
        tool_call_id: String,
        content: String,
    },
}

/// A tool call returned by the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmToolCall {
    pub id: String,
    #[serde(rename = "type")]
    pub call_type: String,
    pub function: LlmFunctionCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmFunctionCall {
    pub name: String,
    pub arguments: String, // JSON string
}

/// Tool definition sent to the LLM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmToolDefinition {
    #[serde(rename = "type")]
    pub tool_type: String,
    pub function: LlmFunctionDef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmFunctionDef {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

/// Parsed response from the LLM.
#[derive(Debug, Clone)]
pub struct LlmResponse {
    pub content: Option<String>,
    pub tool_calls: Option<Vec<LlmToolCall>>,
    pub finish_reason: Option<String>,
}

/// Client for any OpenAI-compatible chat completion API.
#[derive(Clone)]
pub struct LlmClient {
    http: reqwest::Client,
    api_base: String,
    api_key: String,
    model: String,
    max_tokens: u32,
}

impl LlmClient {
    pub fn new(api_base: String, api_key: String, model: String, max_tokens: u32) -> Self {
        Self {
            http: reqwest::Client::new(),
            api_base,
            api_key,
            model,
            max_tokens,
        }
    }

    /// Send a chat completion request with optional tool definitions.
    pub async fn chat(
        &self,
        messages: &[LlmMessage],
        tools: Option<&[LlmToolDefinition]>,
    ) -> Result<LlmResponse, LlmError> {
        let url = format!("{}/chat/completions", self.api_base.trim_end_matches('/'));

        let mut body = serde_json::json!({
            "model": self.model,
            "messages": messages,
            "max_tokens": self.max_tokens,
        });

        if let Some(tool_defs) = tools {
            body["tools"] = serde_json::json!(tool_defs);
        }

        let mut request = self.http.post(&url);
        if !self.api_key.is_empty() {
            request = request.bearer_auth(&self.api_key);
        }

        let response = request
            .json(&body)
            .send()
            .await?;

        let status = response.status().as_u16();
        if status != 200 {
            let body_text = response.text().await.unwrap_or_default();
            return Err(LlmError::Api {
                status,
                body: body_text,
            });
        }

        let response_json: serde_json::Value = response.json().await?;

        self.parse_response(&response_json)
    }

    fn parse_response(&self, json: &serde_json::Value) -> Result<LlmResponse, LlmError> {
        let choice = json["choices"]
            .as_array()
            .and_then(|c| c.first())
            .ok_or(LlmError::EmptyResponse)?;

        let message = &choice["message"];
        let content = message["content"]
            .as_str()
            .map(|s| s.to_string());

        let finish_reason = choice["finish_reason"]
            .as_str()
            .map(|s| s.to_string());

        let tool_calls = if let Some(tc_array) = message["tool_calls"].as_array() {
            let calls: Result<Vec<LlmToolCall>, LlmError> = tc_array
                .iter()
                .map(|tc| {
                    let id = tc["id"].as_str().unwrap_or_default().to_string();
                    let call_type = tc["type"].as_str().unwrap_or("function").to_string();
                    let name = tc["function"]["name"]
                        .as_str()
                        .unwrap_or_default()
                        .to_string();
                    let arguments = tc["function"]["arguments"]
                        .as_str()
                        .unwrap_or("{}")
                        .to_string();

                    Ok(LlmToolCall {
                        id,
                        call_type,
                        function: LlmFunctionCall { name, arguments },
                    })
                })
                .collect();
            Some(calls?)
        } else {
            None
        };

        Ok(LlmResponse {
            content,
            tool_calls,
            finish_reason,
        })
    }
}