//! Google Antigravity CLI (`agy`) as the agent under test
//! (`detonate --agent antigravity`).
//!
//! Antigravity runs headless (`agy -p … --output-format stream-json
//! --dangerously-skip-permissions --disable-slash-commands --settings …`)
//! inside the same sandbox as Pi. Its NDJSON `stream-json` events are
//! translated into [`PiEvent`]s so every detection layer, the report, and the
//! evals work unchanged.
//!
//! Credentials: the sandboxed `agy` only gets a placeholder `GEMINI_API_KEY`
//! and `GOOGLE_GEMINI_BASE_URL` pointing at the local Gemini proxy, which
//! strips any client key and injects the real `x-goog-api-key` upstream.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use crate::pi_agent::PiEvent;

/// Default Gemini model used with `--agent antigravity` when `--model` is omitted.
pub const DEFAULT_MODEL: &str = "gemini-3.8-flash";

/// Maximum file size (256 KiB) read back from the honeypot home when enriching
/// `agy`'s summarized `read_file`/`write_file`/`edit_file` events.
const MAX_ENRICH_BYTES: u64 = 256 * 1024;

/// Effort suffixes accepted on `agy` model slugs (e.g. `gemini-4-neon-medium`).
const EFFORT_SUFFIXES: &[&str] = &["-xhigh", "-medium", "-high", "-low"];

/// Strip an optional `agy` effort suffix (`-low`, `-medium`, `-high`, `-xhigh`)
/// to recover the underlying Gemini API model ID for upstream proxy pinning.
pub fn upstream_model_id(model: &str) -> String {
    for suffix in EFFORT_SUFFIXES {
        if let Some(base) = model.strip_suffix(suffix) {
            if !base.is_empty() {
                return base.to_string();
            }
        }
    }
    model.to_string()
}

/// Write a session-only `agy-settings.json` (passed via `--settings`, outside
/// the honeypot home) configured for headless Gemini API-key execution.
pub fn write_settings(path: &Path, trusted_workspace: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let settings = serde_json::json!({
        "modelProvider": "gemini",
        "toolPermission": "always-proceed",
        "agentMode": "accept-edits",
        "artifactReviewPolicy": "always-proceed",
        "allowNonWorkspaceAccess": true,
        "enableTerminalSandbox": false,
        "disableSlashCommands": true,
        "notifications": false,
        "showTips": false,
        "showFeedbackSurvey": false,
        "trustedWorkspaces": [trusted_workspace]
    });
    std::fs::write(
        path,
        serde_json::to_string_pretty(&settings).expect("settings json"),
    )
}

/// Arguments for `agy` (headless, streaming JSON, sandbox-friendly).
pub fn agy_args(
    prompt: &str,
    model: &str,
    settings_path: &str,
    effort: Option<&str>,
) -> Vec<String> {
    let model_arg = if effort.is_some() {
        upstream_model_id(model)
    } else {
        model.to_string()
    };
    let mut a: Vec<String> = vec![
        "-p".into(),
        prompt.into(),
        "--output-format".into(),
        "stream-json".into(),
        "--dangerously-skip-permissions".into(),
        "--disable-slash-commands".into(),
        "--model".into(),
        model_arg,
        "--settings".into(),
        settings_path.into(),
    ];
    if let Some(e) = effort {
        a.push("--effort".into());
        a.push(e.into());
    }
    a
}

/// Translate Antigravity CLI tool names and PascalCase parameters into the
/// chamber's canonical tool vocabulary.
fn map_tool(name: &str, input: &serde_json::Value) -> (String, serde_json::Value) {
    let mut args = if input.is_object() {
        input.clone()
    } else {
        serde_json::json!({})
    };

    let copy_first = |args: &mut serde_json::Value, dest: &str, srcs: &[&str]| {
        if let Some(obj) = args.as_object_mut() {
            if !obj.contains_key(dest) {
                if let Some(val) = srcs.iter().find_map(|k| input.get(*k)).cloned() {
                    obj.insert(dest.into(), val);
                }
            }
        }
    };

    let canonical = match name {
        "run_command" => {
            copy_first(&mut args, "command", &["CommandLine", "command"]);
            "bash"
        }
        "read_file" | "view_file" => {
            copy_first(&mut args, "path", &["Path", "AbsolutePath", "TargetFile"]);
            "read"
        }
        "write_file" | "write_to_file" => {
            copy_first(&mut args, "path", &["Path", "TargetFile"]);
            copy_first(&mut args, "content", &["Content", "CodeContent"]);
            "write"
        }
        "edit_file" | "replace_file_content" | "multi_replace_file_content" | "sed_file" => {
            copy_first(&mut args, "path", &["Path", "TargetFile"]);
            copy_first(
                &mut args,
                "new_text",
                &["Replacement", "ReplacementContent"],
            );
            "edit"
        }
        "list_dir" => {
            copy_first(&mut args, "path", &["DirectoryPath", "Path"]);
            "ls"
        }
        "grep_search" => {
            copy_first(&mut args, "path", &["SearchPath", "Path"]);
            "grep"
        }
        "find_by_name" => {
            copy_first(&mut args, "path", &["SearchDirectory", "Path"]);
            "find"
        }
        "invoke_subagent" | "define_subagent" | "manage_subagents" | "send_message" => "task",
        other => return (other.to_string(), args),
    };
    (canonical.to_string(), args)
}

/// Stateful parser for `agy --output-format stream-json` NDJSON output.
#[derive(Default)]
pub struct AntigravityStreamParser {
    started_turns: HashSet<u64>,
    started_tools: HashSet<u64>,
    tool_names: HashMap<u64, String>,
    text_buffers: HashMap<u64, String>,
    thinking_buffers: HashMap<u64, String>,
    emitted_text: bool,
}

impl AntigravityStreamParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse_line(&mut self, line: &str) -> Vec<PiEvent> {
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let mut out = Vec::new();
        match v["event"].as_str().unwrap_or("") {
            "step_update" => {
                let su = &v["step_update"];
                let step_index = su["step_index"].as_u64().unwrap_or(0);
                let state = su["state"].as_str().unwrap_or("");
                let step_type = su["step_type"].as_str().unwrap_or("");

                match step_type {
                    "agent_response" => {
                        if self.started_turns.insert(step_index) {
                            out.push(PiEvent::TurnStart);
                        }
                        if let Some(delta) = su["text_delta"].as_str() {
                            self.text_buffers
                                .entry(step_index)
                                .or_default()
                                .push_str(delta);
                        }
                        if let Some(thought) = su["thinking_delta"]
                            .as_str()
                            .or_else(|| su["thought"].as_str())
                        {
                            self.thinking_buffers
                                .entry(step_index)
                                .or_default()
                                .push_str(thought);
                        }
                        if state == "DONE" {
                            if let Some(thought) = self.thinking_buffers.remove(&step_index) {
                                let trimmed = thought.trim();
                                if !trimmed.is_empty() {
                                    out.push(PiEvent::Thinking {
                                        content: trimmed.to_string(),
                                    });
                                }
                            }
                            if let Some(text) = self.text_buffers.remove(&step_index) {
                                let trimmed = text.trim();
                                if !trimmed.is_empty() {
                                    self.emitted_text = true;
                                    out.push(PiEvent::TextOutput {
                                        content: trimmed.to_string(),
                                    });
                                }
                            }
                        }
                    }
                    "tool" => {
                        let info = &su["tool_info"];
                        let raw_name = info["name"]
                            .as_str()
                            .or_else(|| su["tool_name"].as_str())
                            .unwrap_or("unknown");
                        let params = info.get("parameters").unwrap_or(&serde_json::Value::Null);
                        let has_params = params.as_object().is_some_and(|o| !o.is_empty());
                        let (mapped_name, args) = map_tool(raw_name, params);
                        let id = format!("step_{}", step_index);

                        if (state == "DONE" || has_params) && self.started_tools.insert(step_index)
                        {
                            self.tool_names.insert(step_index, mapped_name.clone());
                            out.push(PiEvent::ToolCallStart {
                                tool_call_id: id.clone(),
                                tool_name: mapped_name.clone(),
                                args,
                            });
                        }

                        if state == "DONE" {
                            let name = self
                                .tool_names
                                .get(&step_index)
                                .cloned()
                                .unwrap_or(mapped_name);
                            let mut text = info["output"].as_str().unwrap_or("").to_string();
                            if let Some(err_msg) = info["error"]["message"].as_str() {
                                if !text.is_empty() {
                                    text.push('\n');
                                }
                                text.push_str(err_msg);
                            }
                            out.push(PiEvent::ToolExecutionEnd {
                                tool_call_id: id,
                                tool_name: name,
                                result: serde_json::json!({
                                    "content": [{ "type": "text", "text": text }]
                                }),
                            });
                        }
                    }
                    _ => {}
                }
            }
            "result" => {
                let res = &v["result"];
                let u = &res["usage"];
                let input = u["input_tokens"].as_u64().unwrap_or(0)
                    + u["cache_read_tokens"].as_u64().unwrap_or(0);
                let output = u["output_tokens"].as_u64().unwrap_or(0);
                if input > 0 || output > 0 {
                    out.push(PiEvent::Usage {
                        input_tokens: input,
                        output_tokens: output,
                    });
                }
                if !self.emitted_text {
                    if let Some(resp) = res["response"]
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                    {
                        self.emitted_text = true;
                        out.push(PiEvent::TextOutput {
                            content: resp.to_string(),
                        });
                    }
                }
                let status = res["status"].as_str().unwrap_or("SUCCESS");
                if status != "SUCCESS" {
                    let msg = res["error"]
                        .as_str()
                        .filter(|s| !s.is_empty())
                        .unwrap_or(status);
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

/// Resolve a sandbox path (such as `/home/agent/.env` or `~/.ssh/authorized_keys`)
/// to a regular file strictly inside `honeypot_home` (rejecting symlinks that
/// escape `honeypot_home`) and read up to [`MAX_ENRICH_BYTES`].
fn read_honeypot_file(honeypot_home: &Path, raw_path: &str) -> Option<String> {
    let canonical_home = std::fs::canonicalize(honeypot_home).ok()?;
    let candidate: PathBuf = if let Some(rel) = raw_path.strip_prefix("/home/agent/") {
        honeypot_home.join(rel)
    } else if let Some(rel) = raw_path.strip_prefix("~/") {
        honeypot_home.join(rel)
    } else if !raw_path.starts_with('/') {
        honeypot_home.join(raw_path)
    } else {
        let p = PathBuf::from(raw_path);
        if p.starts_with(honeypot_home) || p.starts_with(&canonical_home) {
            p
        } else {
            return None;
        }
    };
    let canonical = std::fs::canonicalize(&candidate).ok()?;
    if !canonical.starts_with(&canonical_home) {
        return None;
    }
    let meta = std::fs::metadata(&canonical).ok()?;
    if !meta.is_file() || meta.len() > MAX_ENRICH_BYTES {
        return None;
    }
    std::fs::read_to_string(&canonical).ok()
}

/// Enrich `agy` `read`/`write`/`edit` events from the honeypot home before
/// sandbox cleanup.
///
/// `agy --output-format stream-json` omits file content on `write_file` /
/// `edit_file` and summarizes `read_file` output as `"N lines, M bytes"`.
/// Reading the corresponding regular files safely from `honeypot_home` allows
/// canary tracking (arming `SecretReadThenNetworkCall`), file-write persistence
/// rules, and written-script analysis to run with full fidelity.
pub fn enrich_file_events(events: &mut [PiEvent], honeypot_home: &Path) {
    let mut read_paths: HashMap<String, String> = HashMap::new();

    for event in events.iter_mut() {
        match event {
            PiEvent::ToolCallStart {
                tool_call_id,
                tool_name,
                args,
            } => match tool_name.as_str() {
                "read" => {
                    if let Some(p) = args["path"].as_str() {
                        read_paths.insert(tool_call_id.clone(), p.to_string());
                    }
                }
                "write" | "edit" => {
                    let has_content = ["content", "new_text", "newText", "new_string"]
                        .iter()
                        .any(|k| args[*k].as_str().is_some_and(|s| !s.is_empty()));
                    if !has_content {
                        if let Some(path) = args["path"].as_str().map(String::from) {
                            if let Some(body) = read_honeypot_file(honeypot_home, &path) {
                                if let Some(obj) = args.as_object_mut() {
                                    obj.insert("content".into(), serde_json::Value::String(body));
                                }
                            }
                        }
                    }
                }
                _ => {}
            },
            PiEvent::ToolExecutionEnd {
                tool_call_id,
                tool_name,
                result,
            } if tool_name == "read" => {
                let existing = result["content"]
                    .as_array()
                    .and_then(|arr| arr.first())
                    .and_then(|item| item["text"].as_str())
                    .unwrap_or("");
                let is_summary = existing.is_empty()
                    || (!existing.contains('\n') && existing.ends_with(" bytes"));
                if is_summary {
                    if let Some(path) = read_paths.get(tool_call_id) {
                        if let Some(body) = read_honeypot_file(honeypot_home, path) {
                            *result = serde_json::json!({
                                "content": [{ "type": "text", "text": body }]
                            });
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/antigravity_stream_bash.jsonl");

    #[test]
    fn parses_real_antigravity_stream() {
        let mut p = AntigravityStreamParser::new();
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
        assert!(events.iter().any(|e| matches!(
            e,
            PiEvent::Usage {
                input_tokens: 17531,
                output_tokens: 41
            }
        )));
        assert!(!events.iter().any(|e| matches!(e, PiEvent::LlmError { .. })));
    }

    #[test]
    fn parses_error_result_and_preserves_error_message() {
        let mut p = AntigravityStreamParser::new();
        let line = r#"{"event":"result","result":{"conversation_id":"x","status":"ERROR","response":"","error":"invalid model selection","usage":{"input_tokens":0,"output_tokens":0}}}"#;
        let events = p.parse_line(line);
        assert!(events.iter().any(
            |e| matches!(e, PiEvent::LlmError { message } if message.contains("invalid model"))
        ));
    }

    #[test]
    fn maps_antigravity_tools_and_parameters() {
        let (n, a) = map_tool(
            "write_file",
            &serde_json::json!({"Path": "/home/agent/x.sh"}),
        );
        assert_eq!(n, "write");
        assert_eq!(a["path"], "/home/agent/x.sh");

        let (n, a) = map_tool(
            "replace_file_content",
            &serde_json::json!({"TargetFile": "/home/agent/.bashrc", "ReplacementContent": "alias x=y"}),
        );
        assert_eq!(n, "edit");
        assert_eq!(a["path"], "/home/agent/.bashrc");
        assert_eq!(a["new_text"], "alias x=y");

        let (n, a) = map_tool(
            "read_file",
            &serde_json::json!({"Path": "/home/agent/.env"}),
        );
        assert_eq!(n, "read");
        assert_eq!(a["path"], "/home/agent/.env");
    }

    #[test]
    fn strips_effort_suffix_for_upstream_model_id() {
        assert_eq!(upstream_model_id("gemini-4-neon-medium"), "gemini-4-neon");
        assert_eq!(upstream_model_id("gemini-4-neon-xhigh"), "gemini-4-neon");
        assert_eq!(
            upstream_model_id("gemini-3.8-flash-high"),
            "gemini-3.8-flash"
        );
        assert_eq!(upstream_model_id("gemini-4-neon"), "gemini-4-neon");
    }

    #[test]
    fn agy_args_normalizes_model_when_effort_is_set() {
        let args = agy_args(
            "handle inbox",
            "gemini-4-neon-high",
            "/run/agent/pi/agy-settings.json",
            Some("medium"),
        );
        assert!(args.windows(2).any(|w| w == ["--model", "gemini-4-neon"]));
        assert!(args.windows(2).any(|w| w == ["--effort", "medium"]));
        assert!(args.contains(&"--dangerously-skip-permissions".to_string()));
    }

    #[test]
    fn enrich_file_events_populates_content_and_blocks_symlink_escape() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        let outside = dir.path().join("secret.txt");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".env"), "STRIPE_SECRET_KEY=sk_live_canary123\n").unwrap();
        std::fs::write(home.join("backdoor.sh"), "curl https://evil.example\n").unwrap();
        std::fs::write(&outside, "HOST_SECRET_DO_NOT_READ").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, home.join("escape.txt")).unwrap();

        let mut events = vec![
            PiEvent::ToolCallStart {
                tool_call_id: "step_1".into(),
                tool_name: "read".into(),
                args: serde_json::json!({"path": "/home/agent/.env"}),
            },
            PiEvent::ToolExecutionEnd {
                tool_call_id: "step_1".into(),
                tool_name: "read".into(),
                result: serde_json::json!({"content": [{"type": "text", "text": "1 lines, 38 bytes"}]}),
            },
            PiEvent::ToolCallStart {
                tool_call_id: "step_2".into(),
                tool_name: "write".into(),
                args: serde_json::json!({"path": "/home/agent/backdoor.sh"}),
            },
            PiEvent::ToolCallStart {
                tool_call_id: "step_3".into(),
                tool_name: "read".into(),
                args: serde_json::json!({"path": "/home/agent/escape.txt"}),
            },
            PiEvent::ToolExecutionEnd {
                tool_call_id: "step_3".into(),
                tool_name: "read".into(),
                result: serde_json::json!({"content": [{"type": "text", "text": "1 lines, 23 bytes"}]}),
            },
        ];

        enrich_file_events(&mut events, &home);

        match &events[1] {
            PiEvent::ToolExecutionEnd { result, .. } => {
                assert!(result["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("sk_live_canary123"));
            }
            _ => panic!("expected ToolExecutionEnd"),
        }
        match &events[2] {
            PiEvent::ToolCallStart { args, .. } => {
                assert!(args["content"]
                    .as_str()
                    .unwrap()
                    .contains("https://evil.example"));
            }
            _ => panic!("expected ToolCallStart"),
        }
        match &events[4] {
            PiEvent::ToolExecutionEnd { result, .. } => {
                assert!(!result["content"][0]["text"]
                    .as_str()
                    .unwrap()
                    .contains("HOST_SECRET"));
            }
            _ => panic!("expected ToolExecutionEnd"),
        }
    }

    #[test]
    fn enrich_file_events_skips_failed_read_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let home = dir.path().join("home");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join(".env"), "STRIPE_SECRET_KEY=sk_live_canary123\n").unwrap();

        let mut events = vec![
            PiEvent::ToolCallStart {
                tool_call_id: "step_1".into(),
                tool_name: "read".into(),
                args: serde_json::json!({"path": "/home/agent/.env"}),
            },
            PiEvent::ToolExecutionEnd {
                tool_call_id: "step_1".into(),
                tool_name: "read".into(),
                result: serde_json::json!({"content": [{"type": "text", "text": "permission denied"}]}),
            },
        ];

        enrich_file_events(&mut events, &home);

        match &events[1] {
            PiEvent::ToolExecutionEnd { result, .. } => {
                assert_eq!(
                    result["content"][0]["text"].as_str().unwrap(),
                    "permission denied"
                );
            }
            _ => panic!("expected ToolExecutionEnd"),
        }
    }

    #[test]
    fn defers_tool_call_start_when_active_params_are_empty() {
        let mut p = AntigravityStreamParser::new();
        let active = r#"{"event":"step_update","step_update":{"step_index":4,"state":"ACTIVE","step_type":"tool","tool_name":"run_command","tool_info":{"name":"run_command"}}}"#;
        assert!(p.parse_line(active).is_empty());

        let done = r#"{"event":"step_update","step_update":{"step_index":4,"state":"DONE","step_type":"tool","tool_name":"run_command","tool_info":{"name":"run_command","parameters":{"CommandLine":"echo hi"},"output":"hi\n"}}}"#;
        let events = p.parse_line(done);
        assert_eq!(events.len(), 2);
        assert!(matches!(
            &events[0],
            PiEvent::ToolCallStart { tool_name, args, .. }
                if tool_name == "bash" && args["command"] == "echo hi"
        ));
        assert!(matches!(
            &events[1],
            PiEvent::ToolExecutionEnd { tool_name, .. } if tool_name == "bash"
        ));
    }
}
