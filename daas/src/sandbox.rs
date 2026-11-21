//! Process isolation for the detonation agent.
//!
//! The detonation agent runs untrusted instructions with a real `bash` tool, so
//! it must never see the host user's files. With [`Isolation::Bubblewrap`]
//! (the default), Pi runs under `bwrap` with:
//!
//! * a read-only view of the system (`/usr`, `/etc`, …)
//! * `/home`, `/root`, `/media`, `/mnt`, `/run`, `/tmp`, `/var/tmp`, `/srv`
//!   replaced by empty tmpfs mounts, so host secrets are invisible
//! * the honeypot home bind-mounted read-write at `/home/agent`
//! * only the Node runtime and Pi package re-exposed read-only
//! * a cleared environment, private PID/IPC/UTS namespaces, and
//!   `--die-with-parent`
//!
//! Network is shared with the host so the agent can reach the local LLM
//! proxy and the network canary. The real provider API key never enters the
//! sandbox: Pi talks to [`crate::proxy::LlmProxy`] on 127.0.0.1, which adds the
//! key upstream.

use std::path::{Path, PathBuf};

/// How the detonation agent is isolated from the host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Isolation {
    /// Run Pi inside a bubblewrap sandbox (default, requires `bwrap`).
    Bubblewrap,
    /// Run Pi directly on the host with a fake `$HOME`. UNSAFE: the agent's
    /// bash tool can read anything the invoking user can read.
    None,
}

impl Isolation {
    pub fn as_str(&self) -> &'static str {
        match self {
            Isolation::Bubblewrap => "bwrap",
            Isolation::None => "none",
        }
    }
}

/// How to launch Pi: either a native executable, or `node <cli.js>`.
#[derive(Debug, Clone)]
pub struct PiLaunch {
    /// Program to execute (node binary or native pi binary), absolute path.
    pub program: PathBuf,
    /// Leading args (e.g. the cli.js path when running under node).
    pub leading_args: Vec<String>,
    /// Host directories that must be visible (read-only) inside the sandbox.
    pub ro_binds: Vec<PathBuf>,
}

/// Directory inside the sandbox where the honeypot home is mounted.
pub const SANDBOX_HOME: &str = "/home/agent";

/// Resolve the Pi executable into something we can launch inside a sandbox.
pub fn resolve_pi(pi_bin: &str) -> Result<PiLaunch, String> {
    let found =
        which::which(pi_bin).map_err(|e| format!("pi binary '{}' not found: {}", pi_bin, e))?;
    let real = std::fs::canonicalize(&found)
        .map_err(|e| format!("cannot resolve {}: {}", found.display(), e))?;

    let head = std::fs::read(&real)
        .map(|b| b.into_iter().take(128).collect::<Vec<u8>>())
        .unwrap_or_default();
    let head = String::from_utf8_lossy(&head);

    if head.starts_with("#!") && head.lines().next().unwrap_or("").contains("node") {
        // Node script: run it with an absolute node binary so the shebang's
        // `env node` lookup doesn't depend on PATH inside the sandbox.
        let node = which::which("node")
            .map_err(|e| format!("pi is a node script but node was not found: {}", e))?;
        let node = std::fs::canonicalize(&node).map_err(|e| e.to_string())?;
        let node_prefix = node
            .parent()
            .and_then(|p| p.parent())
            .map(Path::to_path_buf)
            .ok_or("cannot determine node install prefix")?;

        // Expose the outermost node_modules directory so all of Pi's
        // dependencies resolve.
        let modules_root = real
            .ancestors()
            .filter(|a| a.file_name().map(|n| n == "node_modules").unwrap_or(false))
            .last()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| real.parent().unwrap_or(Path::new("/")).to_path_buf());

        Ok(PiLaunch {
            program: node,
            leading_args: vec![real.to_string_lossy().into_owned()],
            ro_binds: vec![node_prefix, modules_root],
        })
    } else {
        let dir = real
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("/"));
        Ok(PiLaunch {
            program: real,
            leading_args: vec![],
            ro_binds: vec![dir],
        })
    }
}

/// Check that bubblewrap is installed and can create a sandbox.
pub fn bwrap_available() -> Result<(), String> {
    let bwrap = which::which("bwrap").map_err(|_| {
        "bubblewrap (bwrap) is not installed. Install it (e.g. `sudo apt install bubblewrap`) \
         or pass --no-isolation to run UNSANDBOXED (unsafe)."
            .to_string()
    })?;
    let out = std::process::Command::new(bwrap)
        .args([
            "--ro-bind",
            "/",
            "/",
            "--unshare-pid",
            "--dev",
            "/dev",
            "--proc",
            "/proc",
            "true",
        ])
        .output()
        .map_err(|e| format!("failed to run bwrap: {}", e))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "bwrap cannot create a sandbox on this system: {}. \
             (Unprivileged user namespaces may be disabled.)",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

/// Build the full command (program + args) to run Pi under the chosen
/// isolation. `host_home` is the honeypot home on the host; `env` is the
/// complete environment for the agent (the host environment is NOT inherited).
pub fn build_command(
    isolation: Isolation,
    launch: &PiLaunch,
    host_home: &Path,
    env: &[(String, String)],
    pi_args: &[String],
    extra_hidden: &[PathBuf],
    extra_binds: &[(PathBuf, String)],
) -> tokio::process::Command {
    match isolation {
        Isolation::Bubblewrap => {
            let mut cmd = tokio::process::Command::new("bwrap");
            cmd.env_clear();
            let mut a: Vec<String> = vec![
                "--ro-bind".into(),
                "/".into(),
                "/".into(),
                "--dev".into(),
                "/dev".into(),
                "--proc".into(),
                "/proc".into(),
            ];
            for hidden in [
                "/home",
                "/root",
                "/media",
                "/mnt",
                "/run",
                "/tmp",
                "/var/tmp",
                "/srv",
                "/var/log",
                "/var/mail",
                "/var/backups",
            ] {
                if Path::new(hidden).exists() {
                    a.extend(["--tmpfs".into(), hidden.into()]);
                }
            }
            for hidden in extra_hidden {
                if hidden.exists() {
                    a.extend(["--tmpfs".into(), hidden.to_string_lossy().into_owned()]);
                }
            }
            // DNS on systemd-resolved systems lives under /run.
            a.extend([
                "--ro-bind-try".into(),
                "/run/systemd/resolve".into(),
                "/run/systemd/resolve".into(),
            ]);
            for dir in &launch.ro_binds {
                let d = dir.to_string_lossy().into_owned();
                a.extend(["--ro-bind".into(), d.clone(), d]);
            }
            // Identity: present the agent as user "agent" (fake passwd/group
            // with the invoking uid/gid) so `whoami` matches $HOME.
            if let Some((passwd, group)) = write_identity_files(host_home) {
                a.extend([
                    "--ro-bind".into(),
                    passwd,
                    "/etc/passwd".into(),
                    "--ro-bind".into(),
                    group,
                    "/etc/group".into(),
                ]);
            }
            for (src, dst) in extra_binds {
                a.extend([
                    "--bind".into(),
                    src.to_string_lossy().into_owned(),
                    dst.clone(),
                ]);
            }
            a.extend([
                "--bind".into(),
                host_home.to_string_lossy().into_owned(),
                SANDBOX_HOME.into(),
                "--chdir".into(),
                SANDBOX_HOME.into(),
                "--unshare-pid".into(),
                "--unshare-ipc".into(),
                "--unshare-uts".into(),
                "--hostname".into(),
                "agent-workstation".into(),
                "--die-with-parent".into(),
                "--new-session".into(),
                "--clearenv".into(),
            ]);
            for (k, v) in env {
                a.extend(["--setenv".into(), k.clone(), v.clone()]);
            }
            a.push("--".into());
            a.push(launch.program.to_string_lossy().into_owned());
            a.extend(launch.leading_args.iter().cloned());
            a.extend(pi_args.iter().cloned());
            cmd.args(a);
            cmd
        }
        Isolation::None => {
            let mut cmd = tokio::process::Command::new(&launch.program);
            cmd.env_clear();
            cmd.args(&launch.leading_args);
            cmd.args(pi_args);
            cmd.current_dir(host_home);
            for (k, v) in env {
                // Point HOME at the honeypot home on the host.
                if k == "HOME" {
                    cmd.env(k, host_home);
                } else {
                    cmd.env(k, v);
                }
            }
            cmd
        }
    }
}

/// Write passwd/group files next to the honeypot home that map the invoking
/// uid/gid to user `agent` with home `/home/agent`. Returns their paths.
fn write_identity_files(host_home: &Path) -> Option<(String, String)> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(host_home).ok()?;
    let (uid, gid) = (meta.uid(), meta.gid());
    let dir = host_home.parent()?.parent()?.join("etc");
    std::fs::create_dir_all(&dir).ok()?;
    let keep = |line: &str, id_field: usize| -> bool {
        line.split(':')
            .nth(id_field)
            .and_then(|v| v.parse::<u32>().ok())
            .map(|id| (id < 1000 || id == 65534) && id != uid && id != gid)
            .unwrap_or(false)
    };
    let host_passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    let mut passwd: Vec<String> = host_passwd
        .lines()
        .filter(|l| keep(l, 2))
        .map(String::from)
        .collect();
    passwd.push(format!(
        "agent:x:{}:{}:Agent:/home/agent:/bin/bash",
        uid, gid
    ));
    let host_group = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let mut group: Vec<String> = host_group
        .lines()
        .filter(|l| keep(l, 2))
        .map(|l| {
            // drop member lists (they name host users)
            let mut parts: Vec<&str> = l.splitn(4, ':').collect();
            if parts.len() == 4 {
                parts[3] = "";
            }
            parts.join(":")
        })
        .collect();
    group.push(format!("agent:x:{}:", gid));
    let p = dir.join("passwd");
    let g = dir.join("group");
    std::fs::write(&p, passwd.join("\n") + "\n").ok()?;
    std::fs::write(&g, group.join("\n") + "\n").ok()?;
    Some((
        p.to_string_lossy().into_owned(),
        g.to_string_lossy().into_owned(),
    ))
}
