//! T-633 disposable-node diagnostic. Never run against a resident service.
//! This injects socket ownership, not a daemon or guest cleanup result.
use anyhow::{ensure, Context, Result};
use clap::Parser;
use std::{
    io::{BufRead, Write},
    os::unix::fs::MetadataExt,
    path::PathBuf,
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use uvm_ublk_daemon::{UblkDaemonClient, UblkDaemonSpawnConfig};

#[derive(Parser)]
struct Args {
    /// Explicit acknowledgement: service stopped, guests already preserved.
    #[arg(long)]
    disposable_node_service_stopped: bool,
    #[arg(long)]
    binary: PathBuf,
    #[arg(long)]
    socket: PathBuf,
    #[arg(long)]
    global_config: PathBuf,
    #[arg(long)]
    resize_global_config: PathBuf,
    #[arg(long)]
    app_config: PathBuf,
}

const HOLDER: &str = r#"
import os, selectors, socket, sys
path = sys.argv[1]
s = socket.socket(socket.AF_UNIX)
s.bind(path)
s.listen(128)
poll = selectors.DefaultSelector()
poll.register(s, selectors.EVENT_READ)
poll.register(sys.stdin, selectors.EVENT_READ)
print('HELD', os.getpid(), os.stat(path).st_ino, flush=True)
while True:
    stop = False
    for key, _ in poll.select():
        if key.fileobj is s:
            conn, _ = s.accept()
            conn.close()
        else:
            sys.stdin.readline()
            stop = True
    if stop: break
s.close()
os.unlink(path)
print('RELEASED', flush=True)
"#;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.disposable_node_service_stopped,
        "requires an isolated disposable node with service stopped and guests preserved"
    );
    ensure!(
        !args.socket.exists(),
        "refusing to touch an existing socket"
    );
    let mut holder = Command::new("python3")
        .args(["-u", "-c", HOLDER])
        .arg(&args.socket)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let mut output = std::io::BufReader::new(holder.stdout.take().unwrap());
    let mut ready = String::new();
    output.read_line(&mut ready)?;
    ensure!(
        ready.starts_with("HELD "),
        "holder did not establish socket: {ready}"
    );
    print!("{ready}");
    let inode = std::fs::metadata(&args.socket)?.ino();
    let config = || UblkDaemonSpawnConfig {
        binary_path: &args.binary,
        socket_path: args.socket.clone(),
        global_config: &args.global_config,
        resize_global_config: &args.resize_global_config,
        app_config: Some(&args.app_config),
        log_file: None,
        metrics_listen_addr: "127.0.0.1:0",
        pool_config: None,
        p2p_publish_url: None,
        runtime_device_timeout: Duration::from_secs(30),
    };
    let started = Instant::now();
    let held_result = UblkDaemonClient::new(config()).await;
    let elapsed = started.elapsed();
    // Always command and join the holder before reporting an assertion failure.
    let retained_inode = std::fs::metadata(&args.socket).map(|m| m.ino());
    holder.stdin.take().unwrap().write_all(b"release\n")?;
    let status = holder.wait()?;
    ensure!(status.success(), "socket holder failed");
    match held_result {
        Ok(client) => {
            client.shutdown().await?;
            anyhow::bail!("replacement started while socket was held");
        }
        Err(error) => ensure!(
            format!("{error:#}").contains("still in use after"),
            "wrong failure: {error:#}"
        ),
    }
    ensure!(
        elapsed >= Duration::from_secs(30) && elapsed < Duration::from_secs(35),
        "unexpected socket wait duration: {elapsed:?}"
    );
    ensure!(
        retained_inode.context("socket disappeared before holder release")? == inode,
        "owned socket replaced"
    );
    println!("HELD_TIMEOUT elapsed_ms={}", elapsed.as_millis());
    let client = UblkDaemonClient::new(config())
        .await
        .context("real daemon retry after holder release")?;
    let features = client.get_features().await;
    let stopped = client.shutdown().await;
    println!("REAL_DAEMON features={}", features?);
    stopped?;
    println!("SOCKET_PROBE_PASS; guest restore/fidelity and real-daemon exit evidence must be collected separately");
    Ok(())
}
