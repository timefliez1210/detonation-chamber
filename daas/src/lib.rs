//! DaaS — Detonation-as-a-Service core library.
//!
//! This library provides prompt injection detection by running untrusted payloads
//! through a honeypot sandbox with canary secrets, monitoring for exfiltration attempts
//! across multiple detection layers.

pub mod agent;
pub mod behavioral;
pub mod canary;
pub mod firecracker;
pub mod honeypot;
pub mod llm;
pub mod monitor;
pub mod pi_agent;
pub mod report;
pub mod tools;
pub mod traffic;
pub mod types;
