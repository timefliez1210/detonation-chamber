//! Boots a real Firecracker microVM and runs `pi --version` inside it.
//! Needs /dev/kvm and assets: `vm/fetch-assets.sh && vm/build-rootfs.sh`.
//! Run with: cargo test -p daas --test firecracker_e2e -- --ignored

use daas::firecracker::{FirecrackerConfig, FirecrackerJob, FirecrackerVm};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncReadExt;

#[tokio::test]
#[ignore = "requires /dev/kvm and VM assets in ../vm_assets"]
async fn firecracker_vm_runs_pi_and_streams_output() {
    let assets = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../vm_assets");
    let cfg = FirecrackerConfig::from_assets_dir(&assets);
    cfg.validate().expect("assets present");

    let job_dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(job_dir.path().join("home/agent")).unwrap();
    std::fs::create_dir_all(job_dir.path().join("pi-config")).unwrap();
    let args = vec!["--version".to_string()];
    let env = vec![
        (
            "PATH".to_string(),
            "/usr/local/bin:/usr/bin:/bin".to_string(),
        ),
        ("HOME".to_string(), "/home/agent".to_string()),
    ];
    let job = FirecrackerJob {
        job_dir: job_dir.path(),
        pi_args: &args,
        env: &env,
        forward_ports: &[],
    };

    let mut vm = FirecrackerVm::start(&cfg, job)
        .await
        .expect("VM should start");
    let mut stream = vm
        .output(Duration::from_secs(60))
        .await
        .expect("guest output");
    let mut out = String::new();
    stream.read_to_string(&mut out).await.unwrap();
    assert!(
        out.trim()
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_digit()),
        "unexpected: {out:?}"
    );
    assert!(
        vm.shutdown(Duration::from_secs(15)).await,
        "VM should power off cleanly"
    );
}
