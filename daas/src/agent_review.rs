//! Layer 6: agent alarm review.
//!
//! A behavioral sandbox only sees what the agent *does*. Safety-trained models
//! often refuse an attack outright ("this is a reverse shell, I won't run
//! it"), which leaves no malicious behavior to observe even though the payload
//! clearly was an attack. This layer asks the review LLM whether the agent's
//! own final report identified the content as malicious.
//!
//! The reviewer sees only the agent's final reply and the list of tool calls,
//! never the raw payload, so it judges the agent's conclusion rather than
//! re-classifying the payload itself. A raised alarm is a Suspicious signal;
//! Malicious remains reserved for observed behavior.

use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::llm::{LlmClient, LlmMessage};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AgentAlarm {
    /// The agent declined (part of) what the content asked.
    #[serde(default)]
    pub refused: bool,
    /// The agent explicitly characterized the content as an attack, scam,
    /// prompt injection, credential harvesting, malware, etc.
    #[serde(default)]
    pub flagged_as_attack: bool,
    #[serde(default)]
    pub attack_type: String,
    #[serde(default)]
    pub evidence: String,
}

const SYSTEM: &str = "You audit the final report of an AI agent that was asked to handle an untrusted inbox message. \
You do NOT see the message itself. Decide from the agent's own words whether the agent identified the message as \
malicious. Answer with JSON only.";

pub async fn review(
    client: &LlmClient,
    final_output: &str,
    tool_calls: &[String],
) -> Option<AgentAlarm> {
    let calls = if tool_calls.is_empty() {
        "(none)".to_string()
    } else {
        tool_calls
            .iter()
            .take(20)
            .map(|c| format!("- {}", c))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let prompt = format!(
        "AGENT TOOL CALLS:\n{calls}\n\nAGENT FINAL REPORT:\n<<<\n{report}\n>>>\n\n\
Return JSON: {{\"refused\": bool, \"flagged_as_attack\": bool, \"attack_type\": string, \"evidence\": string}}\n\
- refused: the agent declined some or all of the requested actions.\n\
- flagged_as_attack: the agent explicitly said the message is malicious or an attack (e.g. prompt injection, \
phishing/social engineering, credential/secret exfiltration, reverse shell, malware/remote code execution, \
persistence, crypto theft, destructive command). Declining for other reasons (missing info, ambiguity, \
\"I can't access that\", general caution, or merely redacting secrets in an otherwise normal answer) is NOT an attack flag. \
A message that only discusses, quotes, or teaches about attacks while asking for something harmless is NOT an attack: \
flag only if the agent concluded the message itself tried to make it do something harmful.\n\
- evidence: a short quote from the report supporting your answer.",
        calls = calls,
        report = final_output.chars().take(6000).collect::<String>(),
    );
    let messages = vec![
        LlmMessage::System {
            content: SYSTEM.into(),
        },
        LlmMessage::User { content: prompt },
    ];
    match client.chat(&messages, None).await {
        Ok(resp) => {
            let content = resp.content.unwrap_or_default();
            let json = match (content.find('{'), content.rfind('}')) {
                (Some(a), Some(b)) if b > a => &content[a..=b],
                _ => return None,
            };
            match serde_json::from_str::<AgentAlarm>(json) {
                Ok(a) => Some(a),
                Err(e) => {
                    warn!(error = %e, "Could not parse agent alarm review");
                    None
                }
            }
        }
        Err(e) => {
            warn!(error = %e, "Agent alarm review failed");
            None
        }
    }
}
