//! DaaS — Detonation-as-a-Service core library.
//!
//! This library provides prompt injection detection by running untrusted payloads
//! through a honeypot sandbox with canary secrets, monitoring for exfiltration attempts
//! across multiple detection layers.

pub mod agent;
pub mod agent_review;
pub mod antigravity;
pub mod behavioral;
pub mod canary;
pub mod claude_code;
pub mod firecracker;
pub mod honeypot;
pub mod llm;
pub mod monitor;
pub mod pi_agent;
pub mod proxy;
pub mod report;
pub mod sandbox;
pub mod tools;
pub mod traffic;
pub mod types;

#[cfg(test)]
mod tests_e2e;
