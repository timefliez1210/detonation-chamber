//! Firecracker microVM backend for isolated Pi detonation.
//!
//! Spins up a real Firecracker VM per detonation, runs Pi inside it via SSH,
//! and streams JSONL events back to the host. All honeypot files are copied
//! into the VM before Pi starts.

use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;
use tokio::time::sleep;
use tracing::{info, warn};
use uuid::Uuid;

use crate::pi_agent::PiEvent;

/// Configuration for the Firecracker VM backend.
#[derive(Clone, Debug)]
pub struct FirecrackerConfig {
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub ssh_key_path: PathBuf,
    pub firecracker_bin: PathBuf,
    pub tap_dev: String,
    pub tap_ip: String,
    pub guest_ip: String,
    pub guest_mac: String,
    pub memory_mb: usize,
    pub vcpus: usize,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        Self {
            kernel_path: PathBuf::from("vmlinux"),
            rootfs_path: PathBuf::from("rootfs.ext4"),
            ssh_key_path: PathBuf::from("id_rsa"),
            firecracker_bin: PathBuf::from("firecracker"),
            tap_dev: "tap0".into(),
            tap_ip: "172.16.0.1/30".into(),
            guest_ip: "172.16.0.2".into(),
            guest_mac: "06:00:AC:10:00:02".into(),
            memory_mb: 1024,
            vcpus: 2,
        }
    }
}

/// A running Firecracker microVM session.
pub struct FirecrackerVm {
    config: FirecrackerConfig,
    api_socket: PathBuf,
    vm_id: String,
    _serial_fifo: PathBuf,
}

impl FirecrackerVm {
    /// Start a new Firecracker VM, configure it, and boot.
    pub async fn start(config: FirecrackerConfig) -> Result<Self, String> {
        let vm_id = Uuid::new_v4().to_string();
        let work_dir = std::env::temp_dir().join(format!("daas-fc-{}", &vm_id[..8]));
        std::fs::create_dir_all(&work_dir).map_err(|e| format!("create work dir: {}", e))?;

        let api_socket = work_dir.join("firecracker.socket");
        let serial_fifo = work_dir.join("serial.fifo");

        // Create serial FIFO
        let _ = tokio::fs::remove_file(&serial_fifo).await;
        std::process::Command::new("mkfifo")
            .arg(&serial_fifo)
            .status()
            .map_err(|e| format!("mkfifo: {}", e))?;

        // Setup TAP device (requires CAP_NET_ADMIN or root)
        setup_tap(&config.tap_dev, &config.tap_ip).await?;

        // Start firecracker process
        let mut fc_cmd = Command::new(&config.firecracker_bin);
        fc_cmd
            .arg("--api-sock")
            .arg(&api_socket)
            .arg("--enable-pci")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let _child = fc_cmd.spawn().map_err(|e| format!("spawn firecracker: {}", e))?;

        // Wait for API socket
        for _ in 0..50 {
            if api_socket.exists() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
        if !api_socket.exists() {
            return Err("Firecracker API socket never appeared".into());
        }

        // Give Firecracker a moment to fully initialize its API server
        sleep(Duration::from_millis(800)).await;

        let vm = Self {
            config,
            api_socket,
            vm_id,
            _serial_fifo: serial_fifo,
        };

        // Configure VM via API
        vm.configure().await?;

        info!(vm_id = %vm.vm_id, "Firecracker VM started");
        Ok(vm)
    }

    async fn api_put(&self, path: &str, body: serde_json::Value) -> Result<(), String> {
        let url = format!("http://localhost{}", path);
        let socket = self.api_socket.to_str().unwrap_or("");
        let output = Command::new("curl")
            .args([
                "-fsS", "-X", "PUT",
                "--unix-socket", socket,
                "-H", "Content-Type: application/json",
                "-d", &body.to_string(),
                &url,
            ])
            .output()
            .await
            .map_err(|e| format!("curl {}: {}", path, e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("API {} failed: {}", path, stderr));
        }
        Ok(())
    }

    #[allow(dead_code)]
    async fn api_post(&self, path: &str, body: serde_json::Value) -> Result<(), String> {
        let url = format!("http://localhost{}", path);
        let socket = self.api_socket.to_str().unwrap_or("");
        let output = Command::new("curl")
            .args([
                "-fsS", "-X", "POST",
                "--unix-socket", socket,
                "-H", "Content-Type: application/json",
                "-d", &body.to_string(),
                &url,
            ])
            .output()
            .await
            .map_err(|e| format!("curl {}: {}", path, e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("API {} failed: {}", path, stderr));
        }
        Ok(())
    }

    async fn configure(&self) -> Result<(), String> {
        // Boot source
        self.api_put(
            "/boot-source",
            serde_json::json!({
                "kernel_image_path": self.config.kernel_path,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off"
            }),
        )
        .await?;

        // Root drive
        self.api_put(
            "/drives/rootfs",
            serde_json::json!({
                "drive_id": "rootfs",
                "path_on_host": self.config.rootfs_path,
                "is_root_device": true,
                "is_read_only": false
            }),
        )
        .await?;

        // Network
        self.api_put(
            "/network-interfaces/net1",
            serde_json::json!({
                "iface_id": "net1",
                "guest_mac": self.config.guest_mac,
                "host_dev_name": self.config.tap_dev
            }),
        )
        .await?;

        // Machine config
        self.api_put(
            "/machine-config",
            serde_json::json!({
                "vcpu_count": self.config.vcpus,
                "mem_size_mib": self.config.memory_mb
            }),
        )
        .await?;

        // Start instance
        sleep(Duration::from_millis(50)).await;
        self.api_put(
            "/actions",
            serde_json::json!({ "action_type": "InstanceStart" }),
        )
        .await?;

        Ok(())
    }

    /// Copy local directory into VM via SCP.
    pub async fn scp_copy(&self, local_dir: &str, remote_dir: &str) -> Result<(), String> {
        // Use rsync or scp via ssh key
        let output = Command::new("scp")
            .args([
                "-i", self.config.ssh_key_path.to_str().unwrap_or(""),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-r", local_dir,
                &format!("root@{}:{}", self.config.guest_ip, remote_dir),
            ])
            .output()
            .await
            .map_err(|e| format!("scp: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("scp failed: {}", stderr));
        }
        Ok(())
    }

    /// Run a command inside the VM via SSH, return stdout lines.
    pub async fn ssh_exec(&self, command: &str) -> Result<std::process::Output, String> {
        let output = Command::new("ssh")
            .args([
                "-i", self.config.ssh_key_path.to_str().unwrap_or(""),
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=5",
                &format!("root@{}", self.config.guest_ip),
                command,
            ])
            .output()
            .await
            .map_err(|e| format!("ssh: {}", e))?;
        Ok(output)
    }

    /// Wait until SSH responds (guest has booted).
    pub async fn wait_for_ssh(&self, timeout_secs: u64) -> Result<(), String> {
        // Give the VM a few seconds to boot before we start hammering ARP
        sleep(Duration::from_secs(5)).await;
        let start = tokio::time::Instant::now();
        loop {
            if start.elapsed().as_secs() > timeout_secs {
                return Err("SSH never became available".into());
            }
            match self.ssh_exec("echo ready").await {
                Ok(out) => {
                    let stdout = String::from_utf8_lossy(&out.stdout);
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    eprintln!("[wait_for_ssh] status={:?} stdout={} stderr={}", out.status, stdout.trim(), stderr.trim());
                    if out.status.success() {
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[wait_for_ssh] ssh_exec error: {}", e);
                }
            }
            sleep(Duration::from_millis(300)).await;
        }
        Ok(())
    }

    /// Run Pi inside the VM with the given payload and sandbox directory.
    pub async fn run_pi(
        &self,
        payload: &str,
        sandbox_dir: &str,
        pi_args: &[String],
    ) -> Result<(Vec<PiEvent>, String, usize), String> {
        // Wait for guest boot
        self.wait_for_ssh(30).await?;

        // Copy sandbox into VM
        let remote_sandbox = format!("/tmp/daas-sandbox-{}", &self.vm_id[..8]);
        let _ = self.ssh_exec(&format!("mkdir -p {}", remote_sandbox)).await;
        self.scp_copy(sandbox_dir, &remote_sandbox).await?;

        // Ensure remote pi binary exists
        let check = self.ssh_exec("which pi || which /usr/local/bin/pi").await?;
        if !check.status.success() {
            // Try to find pi
            let find = self.ssh_exec("find /usr -name cli.js 2>/dev/null | head -1").await?;
            let pi_path = String::from_utf8_lossy(&find.stdout).trim().to_string();
            if pi_path.is_empty() {
                return Err("pi binary not found inside VM".into());
            }
            let _ = self.ssh_exec(&format!("ln -sf {} /usr/local/bin/pi", pi_path)).await;
        }

        // Build pi command
        let pi_cmd = format!(
            "cd {} && OLLAMA_HOST=http://{}:11434 /usr/local/bin/pi --mode json --print --no-session {} '{}'",
            remote_sandbox,
            self.config.tap_ip.split('/').next().unwrap_or("172.16.0.1"),
            pi_args.join(" "),
            shell_escape(payload)
        );

        info!(cmd = %pi_cmd, "Running Pi in Firecracker VM");

        let output = self.ssh_exec(&pi_cmd).await?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        if !stderr.is_empty() {
            warn!(stderr = %stderr, "Pi stderr from VM");
        }

        // Parse JSONL
        let mut events = Vec::new();
        let mut turns = 0;
        for line in stdout.lines() {
            if let Some(event) = crate::pi_agent::parse_pi_event(line) {
                if matches!(event, PiEvent::ToolCallStart { .. }) {
                    turns += 1;
                }
                events.push(event);
            }
        }

        let terminated_reason = if output.status.success() {
            "natural_stop"
        } else {
            "vm_error"
        };

        Ok((events, terminated_reason.to_string(), turns))
    }

    /// Kill the VM.
    pub async fn kill(&self) -> Result<(), String> {
        // Send graceful shutdown via API (FlushMetrics or just terminate)
        let _ = self
            .api_put("/actions", serde_json::json!({ "action_type": "SendCtrlAltDel" }))
            .await;
        sleep(Duration::from_millis(500)).await;

        // Clean up TAP
        let _ = Command::new("ip")
            .args(["link", "del", &self.config.tap_dev])
            .output()
            .await;

        // Clean up temp files
        let _ = tokio::fs::remove_dir_all(&self.api_socket.parent().unwrap()).await;

        info!(vm_id = %self.vm_id, "Firecracker VM killed");
        Ok(())
    }
}

fn shell_escape(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\"'\"'"))
}

async fn setup_tap(tap_dev: &str, tap_cidr: &str) -> Result<(), String> {
    // Delete old tap if exists
    let del_out = Command::new("ip")
        .args(["link", "del", tap_dev])
        .output()
        .await;
    eprintln!("[setup_tap] ip link del {} -> {:?}", tap_dev, del_out);

    let add_out = Command::new("ip")
        .args(["tuntap", "add", "dev", tap_dev, "mode", "tap"])
        .output()
        .await;
    eprintln!("[setup_tap] ip tuntap add {} -> status={:?} stderr={}", tap_dev, add_out.as_ref().map(|o| o.status), add_out.as_ref().map(|o| String::from_utf8_lossy(&o.stderr).to_string()).unwrap_or_default());

    let addr_out = Command::new("ip")
        .args(["addr", "add", tap_cidr, "dev", tap_dev])
        .output()
        .await;
    eprintln!("[setup_tap] ip addr add {} dev {} -> status={:?} stderr={}", tap_cidr, tap_dev, addr_out.as_ref().map(|o| o.status), addr_out.as_ref().map(|o| String::from_utf8_lossy(&o.stderr).to_string()).unwrap_or_default());

    let up_out = Command::new("ip")
        .args(["link", "set", "dev", tap_dev, "up"])
        .output()
        .await;
    eprintln!("[setup_tap] ip link set dev {} up -> status={:?} stderr={}", tap_dev, up_out.as_ref().map(|o| o.status), up_out.as_ref().map(|o| String::from_utf8_lossy(&o.stderr).to_string()).unwrap_or_default());

    // Verify
    let verify = Command::new("ip")
        .args(["addr", "show", "dev", tap_dev])
        .output()
        .await;
    eprintln!("[setup_tap] ip addr show dev {} -> {}", tap_dev, verify.map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default());

    // Enable forwarding
    let _ = Command::new("sh")
        .args(["-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"])
        .output()
        .await;

    // MASQUERADE so VM can reach host services (Ollama)
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-j", "MASQUERADE"])
        .output()
        .await;

    // Allow forwarding between TAP and external interface
    let _ = Command::new("iptables")
        .args(["-A", "FORWARD", "-i", tap_dev, "-o", "eth0", "-j", "ACCEPT"])
        .output()
        .await;
    let _ = Command::new("iptables")
        .args(["-A", "FORWARD", "-i", "eth0", "-o", tap_dev, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        .output()
        .await;

    Ok(())
}
