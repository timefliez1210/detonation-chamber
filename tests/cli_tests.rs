//! CLI integration tests for detonate.

use std::process::Command;

fn detonate_bin() -> Command {
    // Cargo sets this env var during integration tests, pointing to the exact binary
    if let Ok(path) = std::env::var("CARGO_BIN_EXE_detonate") {
        Command::new(path)
    } else {
        Command::new("target/debug/detonate")
    }
}

#[test]
fn test_help_flag() {
    let out = detonate_bin()
        .arg("--help")
        .output()
        .expect("failed to run detonate --help");

    assert!(out.status.success(), "--help should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("detonate"), "help should mention tool name");
    assert!(stdout.contains("--output"), "help should list --output");
    assert!(
        stdout.contains("--payload-file"),
        "help should list --payload-file"
    );
}

#[test]
fn test_version_flag() {
    let out = detonate_bin()
        .arg("--version")
        .output()
        .expect("failed to run detonate --version");

    assert!(out.status.success(), "--version should succeed");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("0.1.0"), "version should be 0.1.0");
}

#[test]
fn test_required_pi_binary_error() {
    // Without pi installed and without --firecracker, should exit 3
    let out = detonate_bin()
        .arg("--output")
        .arg("quiet")
        .arg("safe payload")
        .env("PI_BIN", "/nonexistent/pi_binary")
        .output()
        .expect("failed to run");

    assert!(!out.status.success(), "should fail without pi");
    assert_eq!(
        out.status.code(),
        Some(3),
        "should exit 3 when pi binary not found"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Pi binary"),
        "stderr should mention Pi binary"
    );
}

#[test]
fn test_payload_size_guard() {
    use std::io::Write;

    let huge_payload = "x".repeat(1_000_001);
    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "{}", huge_payload).unwrap();

    let out = detonate_bin()
        .arg("--output")
        .arg("quiet")
        .arg("--payload-file")
        .arg(tmp.path())
        .output()
        .expect("failed to run");

    assert_eq!(
        out.status.code(),
        Some(3),
        "should exit 3 due to payload size limit"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("too large"),
        "stderr should say payload too large"
    );
}

#[test]
fn test_payload_file_reads_file() {
    use std::io::Write;

    let mut tmp = tempfile::NamedTempFile::new().unwrap();
    write!(tmp, "test payload from file").unwrap();

    // This will fail because pi isn't installed, but it proves --payload-file works
    let out = detonate_bin()
        .arg("--payload-file")
        .arg(tmp.path())
        .arg("--output")
        .arg("quiet")
        .output()
        .expect("failed to run");

    // Should NOT fail with "No payload provided" or "Error reading payload file"
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("Error reading payload file"),
        "stderr should not complain about reading file: {}",
        stderr
    );
}
