use std::path::PathBuf;
use daas::firecracker::{FirecrackerConfig, FirecrackerVm};

#[tokio::test]
async fn firecracker_vm_boots_and_ssh_works() {
    let assets = PathBuf::from("/vm_assets");
    let config = FirecrackerConfig {
        kernel_path: assets.join("vmlinux"),
        rootfs_path: assets.join("rootfs.ext4"),
        ssh_key_path: assets.join("id_rsa"),
        firecracker_bin: PathBuf::from("firecracker"),
        tap_dev: "fc_tap0".into(),
        tap_ip: "172.16.0.1/30".into(),
        guest_ip: "172.16.0.2".into(),
        guest_mac: "06:00:AC:10:00:02".into(),
        memory_mb: 1024,
        vcpus: 2,
    };

    let vm = FirecrackerVm::start(config).await.expect("VM should start");

    // Wait for SSH with a longer timeout for first boot
    vm.wait_for_ssh(60).await.expect("SSH should become available");

    // Run a simple command
    let output = vm.ssh_exec("echo hello-from-vm").await.expect("ssh command should run");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello-from-vm"), "Unexpected stdout: {}", stdout);

    vm.kill().await.expect("VM should be killed cleanly");
}
