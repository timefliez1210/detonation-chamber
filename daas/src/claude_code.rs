//! Claude Code as the agent under test (`detonate --agent claude-code`).
//!
//! Claude Code runs headless (`claude -p … --output-format stream-json
//! --verbose --bare`) inside the same sandbox as Pi. Its stream-json events
//! are translated into [`PiEvent`]s so every detection layer, the report, and
//! the evals work unchanged. Tool calls made by subagents (`Task`) appear in
//! the same stream and are analyzed like the main agent's.
//!
//! Credentials: the sandboxed Claude Code only gets a placeholder
//! `ANTHROPIC_API_KEY` and `ANTHROPIC_BASE_URL` pointing at the local proxy,
//! which adds the real credential (a subscription token from
//! `claude setup-token`, or a Console API key). `--bare` makes Claude Code
//! ignore any local login, keychain, settings, hooks, and plugins.

use std::collections::HashMap;

use crate::pi_agent::PiEvent;

/// Built-in tools given to Claude Code (comparable to Pi's read/bash/edit/write,
/// plus Task so subagents are part of the test).
pub const DEFAULT_TOOLS: &str = "Bash,Read,Write,Edit,Glob,Grep,Task";

/// Translate Claude Code tool names/arguments to the chamber's vocabulary.
fn map_tool(name: &str, input: &serde_json::Value) -> (String, serde_json::Value) {
    let n = match name {
        "Bash" => "bash",
        "Read" => "read",
        "Write" => "write",
        "Edit" | "MultiEdit" | "NotebookEdit" => "edit",
        "Glob" => "find",
        "Grep" => "grep",
        "LS" => "ls",
        // Delegation and bookkeeping tools carry no side effects themselves;
        // the subagent's own tool calls are analyzed when they happen.
        "Task" | "Agent" => "task",
        "TodoWrite" | "TodoRead" => "todo",
        other => return (other.to_string(), input.clone()),
    };
    let mut args = input.clone();
    // Claude Code uses `file_path`; the analyzers accept `path` or `file_path`.
    if let (Some(fp), Some(obj)) = (input.get("file_path").cloned(), args.as_object_mut()) {
        obj.entry("path").or_insert(fp);
    }
    (n.to_string(), args)
}

/// Stateful parser for Claude Code's stream-json output.
#[derive(Default)]
pub struct ClaudeStreamParser {
    last_message_id: Option<String>,
    tool_names: HashMap<String, String>,
}

impl ClaudeStreamParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_line(&mut self, line: &str) -> Vec<PiEvent> {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        match v["type"].as_str().unwrap_or("") {
            "assistant" => {
                let msg = &v["message"];
                let id = msg["id"].as_str().map(String::from);
                if id.is_some() && id != self.last_message_id {
                    self.last_message_id = id;
                    out.push(PiEvent::TurnStart);
                }
                if let Some(items) = msg["content"].as_array() {
                    for item in items {
                        match item["type"].as_str() {
                            Some("text") => {
                                if let Some(t) =
                                    item["text"].as_str().filter(|t| !t.trim().is_empty())
                                {
                                    out.push(PiEvent::TextOutput {
                                        content: t.to_string(),
                                    });
                                }
                            }
                            Some("thinking") => {
                                if let Some(t) = item["thinking"].as_str() {
                                    out.push(PiEvent::Thinking {
                                        content: t.to_string(),
                                    });
                                }
                            }
                            Some("tool_use") => {
                                let id = item["id"].as_str().unwrap_or("").to_string();
                                let raw = item["name"].as_str().unwrap_or("unknown");
                                let (name, args) = map_tool(raw, &item["input"]);
                                self.tool_names.insert(id.clone(), name.clone());
                                out.push(PiEvent::ToolCallStart {
                                    tool_call_id: id,
                                    tool_name: name,
                                    args,
                                });
                            }
                            _ => {}
                        }
                    }
                }
            }
            "user" => {
                if let Some(items) = v["message"]["content"].as_array() {
                    for item in items {
                        if item["type"].as_str() != Some("tool_result") {
                            continue;
                        }
                        let id = item["tool_use_id"].as_str().unwrap_or("").to_string();
                        let text = match &item["content"] {
                            serde_json::Value::String(s) => s.clone(),
                            serde_json::Value::Array(parts) => parts
                                .iter()
                                .filter_map(|p| p["text"].as_str())
                                .collect::<Vec<_>>()
                                .join("\n"),
                            other => other.to_string(),
                        };
                        let name = self
                            .tool_names
                            .get(&id)
                            .cloned()
                            .unwrap_or_else(|| "unknown".into());
                        out.push(PiEvent::ToolExecutionEnd {
                            tool_call_id: id,
                            tool_name: name,
                            result: serde_json::json!({ "content": [{ "type": "text", "text": text }] }),
                        });
                    }
                }
            }
            "result" => {
                let u = &v["usage"];
                let input = u["input_tokens"].as_u64().unwrap_or(0)
                    + u["cache_read_input_tokens"].as_u64().unwrap_or(0)
                    + u["cache_creation_input_tokens"].as_u64().unwrap_or(0);
                let output = u["output_tokens"].as_u64().unwrap_or(0);
                if input > 0 || output > 0 {
                    out.push(PiEvent::Usage {
                        input_tokens: input,
                        output_tokens: output,
                    });
                }
                let is_error = v["is_error"].as_bool().unwrap_or(false)
                    || v["subtype"]
                        .as_str()
                        .map(|s| s != "success")
                        .unwrap_or(false);
                if is_error {
                    let msg = v["result"]
                        .as_str()
                        .or_else(|| v["subtype"].as_str())
                        .unwrap_or("Claude Code reported an error");
                    out.push(PiEvent::LlmError {
                        message: msg.to_string(),
                    });
                }
            }
            _ => {}
        }
        out
    }
}

/// Arguments for `claude` (headless, streaming JSON, sandbox-friendly).
pub fn claude_args(
    prompt: &str,
    model: &str,
    tools: &str,
    append_system: Option<&str>,
    effort: Option<&str>,
) -> Vec<String> {
    let mut a: Vec<String> = vec![
        "-p".into(),
        prompt.into(),
        "--output-format".into(),
        "stream-json".into(),
        "--verbose".into(),
        "--bare".into(),
        "--permission-mode".into(),
        "bypassPermissions".into(),
        "--model".into(),
        model.into(),
        "--tools".into(),
        tools.into(),
        // Include subagents' text/thinking in the stream (their tool calls are
        // analyzed either way).
        "--forward-subagent-text".into(),
    ];
    if let Some(e) = effort {
        a.push("--effort".into());
        a.push(e.into());
    }
    if let Some(s) = append_system {
        a.push("--append-system-prompt".into());
        a.push(s.into());
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/claude_stream_bash.jsonl");

    #[test]
    fn parses_real_claude_code_stream() {
        let mut p = ClaudeStreamParser::new();
        let events: Vec<PiEvent> = FIXTURE.lines().flat_map(|l| p.parse_line(l)).collect();
        let calls: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                PiEvent::ToolCallStart {
                    tool_name, args, ..
                } => Some((tool_name.clone(), args.clone())),
                _ => None,
            })
            .collect();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "bash");
        assert!(calls[0].1["command"]
            .as_str()
            .unwrap()
            .contains("fixture-ok"));
        assert!(events.iter().any(
            |e| matches!(e, PiEvent::ToolExecutionEnd { tool_name, .. } if tool_name == "bash")
        ));
        assert!(events
            .iter()
            .any(|e| matches!(e, PiEvent::TextOutput { content } if content == "done")));
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, PiEvent::TurnStart))
                .count(),
            2
        );
        assert!(events.iter().any(|e| matches!(e, PiEvent::Usage { .. })));
        assert!(!events.iter().any(|e| matches!(e, PiEvent::LlmError { .. })));
    }

    #[test]
    fn maps_write_file_path() {
        let (n, a) = map_tool(
            "Write",
            &serde_json::json!({"file_path": "/home/agent/x.sh", "content": "hi"}),
        );
        assert_eq!(n, "write");
        assert_eq!(a["path"], "/home/agent/x.sh");
    }
}
