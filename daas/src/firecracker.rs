//! Firecracker microVM backend (`detonate --firecracker`).
//!
//! The agent runs in its own kernel. The VM has **no network interface**:
//! the only ways out are virtio-vsock tunnels that the host opens on purpose:
//!
//! * guest `127.0.0.1:<proxy port>`  → host LLM proxy (adds the API key)
//! * guest `127.0.0.1:<canary port>` → host network canary
//! * guest → host vsock port 5000: Pi's JSONL output stream
//!
//! Each run gets a fresh job disk (`/dev/vdb`, built with `mkfs.ext4 -d`
//! from the honeypot directory) and boots the shared root image read-only; the
//! guest init (`vm/detonate-init`) puts a RAM overlay on top, so nothing a
//! payload does persists. Nothing here needs root: only access to `/dev/kvm`.
//!
//! Assets (`vm_assets/`): `firecracker`, `vmlinux`, `rootfs.ext4`; see
//! `vm/fetch-assets.sh` and `vm/build-rootfs.sh`.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use tokio::net::{TcpStream, UnixListener, UnixStream};
use tracing::{info, warn};

/// vsock port on which the guest streams Pi's stdout to the host.
pub const OUTPUT_PORT: u16 = 5000;

#[derive(Debug, Clone)]
pub struct FirecrackerConfig {
    pub firecracker_bin: PathBuf,
    pub kernel_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub memory_mb: usize,
    pub vcpus: usize,
}

impl FirecrackerConfig {
    /// Config for an assets directory containing `vmlinux`, `rootfs.ext4` and
    /// (optionally) a `firecracker` binary; falls back to `firecracker` on PATH.
    pub fn from_assets_dir(dir: &Path) -> Self {
        let bundled = dir.join("firecracker");
        Self {
            firecracker_bin: if bundled.exists() {
                bundled
            } else {
                PathBuf::from("firecracker")
            },
            kernel_path: dir.join("vmlinux"),
            rootfs_path: dir.join("rootfs.ext4"),
            memory_mb: 2048,
            vcpus: 2,
        }
    }

    /// Check that everything needed to boot is present.
    pub fn validate(&self) -> Result<(), String> {
        for (what, p) in [("kernel", &self.kernel_path), ("rootfs", &self.rootfs_path)] {
            if !p.exists() {
                return Err(format!(
                    "Firecracker {} not found: {} (run vm/fetch-assets.sh and vm/build-rootfs.sh)",
                    what,
                    p.display()
                ));
            }
        }
        if which::which(&self.firecracker_bin).is_err() && !self.firecracker_bin.exists() {
            return Err(format!(
                "firecracker binary not found ({}); run vm/fetch-assets.sh",
                self.firecracker_bin.display()
            ));
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
            .map_err(|e| {
                format!(
                    "cannot open /dev/kvm ({}); add your user to the kvm group",
                    e
                )
            })?;
        Ok(())
    }
}

/// What to run inside the VM.
pub struct FirecrackerJob<'a> {
    /// Host directory containing `home/agent/` and `pi-config/`; it becomes the
    /// job disk (mounted at /mnt/job in the guest).
    pub job_dir: &'a Path,
    /// Arguments for `pi`.
    pub pi_args: &'a [String],
    /// Complete environment for Pi (nothing else is inherited).
    pub env: &'a [(String, String)],
    /// Host 127.0.0.1 TCP ports to expose inside the guest on the same port.
    pub forward_ports: &'a [u16],
}

/// A running microVM. Dropping it kills the VM and removes its workspace.
pub struct FirecrackerVm {
    child: tokio::process::Child,
    workdir: PathBuf,
    output_listener: UnixListener,
    job_image: PathBuf,
}

impl FirecrackerVm {
    /// Build the job disk, open the vsock tunnels, and boot the VM.
    pub async fn start(cfg: &FirecrackerConfig, job: FirecrackerJob<'_>) -> Result<Self, String> {
        // Unix socket paths must be < 108 bytes, so use a short dir in /tmp.
        let id = uuid::Uuid::new_v4().simple().to_string()[..12].to_string();
        let workdir = PathBuf::from(format!("/tmp/dcfc-{}", id));
        std::fs::create_dir_all(&workdir)
            .map_err(|e| format!("create {}: {}", workdir.display(), e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&workdir, std::fs::Permissions::from_mode(0o700));
        }

        // ── Job files ────────────────────────────────────────────────
        let jobmeta = job.job_dir.join("job");
        std::fs::create_dir_all(&jobmeta).map_err(|e| e.to_string())?;
        let mut args = Vec::new();
        for a in job.pi_args {
            args.extend_from_slice(a.as_bytes());
            args.push(0);
        }
        std::fs::write(jobmeta.join("args"), args).map_err(|e| e.to_string())?;
        let env: String = job
            .env
            .iter()
            .map(|(k, v)| format!("{}={}\n", k, v.replace('\n', " ")))
            .collect();
        std::fs::write(jobmeta.join("env"), env).map_err(|e| e.to_string())?;
        let ports: Vec<String> = job.forward_ports.iter().map(|p| p.to_string()).collect();
        std::fs::write(jobmeta.join("ports"), ports.join(" ")).map_err(|e| e.to_string())?;

        // ── Job disk ─────────────────────────────────────────────────
        let job_image = workdir.join("job.ext4");
        let size_mb = dir_size(job.job_dir) / (1024 * 1024) + 256;
        let f = std::fs::File::create(&job_image).map_err(|e| e.to_string())?;
        f.set_len(size_mb * 1024 * 1024)
            .map_err(|e| e.to_string())?;
        drop(f);
        let mkfs = tokio::process::Command::new("mkfs.ext4")
            .args(["-q", "-F", "-L", "job", "-d"])
            .arg(job.job_dir)
            .arg(&job_image)
            .output()
            .await
            .map_err(|e| format!("mkfs.ext4 not available: {}", e))?;
        if !mkfs.status.success() {
            return Err(format!(
                "mkfs.ext4 failed: {}",
                String::from_utf8_lossy(&mkfs.stderr)
            ));
        }

        // ── vsock tunnels (guest-initiated → host unix sockets) ──────
        let uds = workdir.join("v.sock");
        let output_listener = UnixListener::bind(format!("{}_{}", uds.display(), OUTPUT_PORT))
            .map_err(|e| format!("bind vsock output socket: {}", e))?;
        for &port in job.forward_ports {
            let listener = UnixListener::bind(format!("{}_{}", uds.display(), port))
                .map_err(|e| format!("bind vsock tunnel {}: {}", port, e))?;
            tokio::spawn(async move {
                while let Ok((mut guest, _)) = listener.accept().await {
                    tokio::spawn(async move {
                        match TcpStream::connect(("127.0.0.1", port)).await {
                            Ok(mut host) => {
                                let _ = tokio::io::copy_bidirectional(&mut guest, &mut host).await;
                            }
                            Err(e) => warn!(port, error = %e, "vsock tunnel: host connect failed"),
                        }
                    });
                }
            });
        }

        // ── VM config + boot ─────────────────────────────────────────
        let config = serde_json::json!({
            "boot-source": {
                "kernel_image_path": cfg.kernel_path,
                "boot_args": "console=ttyS0 reboot=k panic=1 pci=off quiet init=/sbin/detonate-init"
            },
            "drives": [
                { "drive_id": "root", "path_on_host": cfg.rootfs_path, "is_root_device": true, "is_read_only": true },
                { "drive_id": "job", "path_on_host": job_image, "is_root_device": false, "is_read_only": false }
            ],
            "machine-config": { "vcpu_count": cfg.vcpus, "mem_size_mib": cfg.memory_mb },
            "vsock": { "guest_cid": 3, "uds_path": uds }
        });
        let cfg_path = workdir.join("vm.json");
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&config).unwrap())
            .map_err(|e| e.to_string())?;
        let console =
            std::fs::File::create(workdir.join("console.log")).map_err(|e| e.to_string())?;
        let console_err = console.try_clone().map_err(|e| e.to_string())?;

        let child = tokio::process::Command::new(&cfg.firecracker_bin)
            .arg("--no-api")
            .arg("--config-file")
            .arg(&cfg_path)
            .stdin(Stdio::null())
            .stdout(Stdio::from(console))
            .stderr(Stdio::from(console_err))
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("spawn firecracker: {}", e))?;
        info!(workdir = %workdir.display(), "Firecracker VM started");

        Ok(Self {
            child,
            workdir,
            output_listener,
            job_image,
        })
    }

    /// Wait for the guest to connect its output stream.
    pub async fn output(&mut self, timeout: Duration) -> Result<UnixStream, String> {
        let accepted = tokio::select! {
            r = tokio::time::timeout(timeout, self.output_listener.accept()) => Some(r),
            _ = self.child.wait() => None,
        };
        match accepted {
            Some(Ok(Ok((stream, _)))) => Ok(stream),
            Some(Ok(Err(e))) => Err(format!("vsock accept failed: {}", e)),
            Some(Err(_)) => Err(format!(
                "VM did not start Pi within {}s{}",
                timeout.as_secs(),
                self.console_hint()
            )),
            None => Err(format!(
                "VM exited before Pi started{}",
                self.console_hint()
            )),
        }
    }

    /// Wait for the VM to power off (up to `timeout`), then kill it.
    pub async fn shutdown(&mut self, timeout: Duration) -> bool {
        match tokio::time::timeout(timeout, self.child.wait()).await {
            Ok(Ok(status)) => status.success(),
            _ => {
                let _ = self.child.kill().await;
                false
            }
        }
    }

    pub async fn kill(&mut self) {
        let _ = self.child.kill().await;
    }

    /// Pi's stderr from the guest, read back from the job disk (best effort,
    /// needs `debugfs`; call after the VM has stopped).
    pub async fn guest_stderr(&self) -> String {
        let out = tokio::process::Command::new("debugfs")
            .args(["-R", "cat /job/stderr"])
            .arg(&self.job_image)
            .stderr(Stdio::null())
            .output()
            .await;
        match out {
            Ok(o) => String::from_utf8_lossy(&o.stdout).into_owned(),
            Err(_) => String::new(),
        }
    }

    fn console_hint(&self) -> String {
        let log = std::fs::read_to_string(self.workdir.join("console.log")).unwrap_or_default();
        let lines: Vec<&str> = log.lines().filter(|l| !l.trim().is_empty()).collect();
        let tail = lines[lines.len().saturating_sub(5)..].join(" | ");
        if tail.is_empty() {
            String::new()
        } else {
            format!(" — console: {}", tail)
        }
    }
}

impl Drop for FirecrackerVm {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.workdir);
    }
}

fn dir_size(p: &Path) -> u64 {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(p) {
        for e in entries.flatten() {
            match e.metadata() {
                Ok(m) if m.is_dir() => total += dir_size(&e.path()),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}
