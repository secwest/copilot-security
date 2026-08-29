use std::env;
use tokio::process::Command;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let marker = env::var("RUST_COMMAND_MARKER").expect("marker must be set");
    let payload = "diagnostic; printf $RUST_COMMAND_MARKER";
    let output = Command::new("printf")
        .arg("%s")
        .arg(payload)
        .env("RUST_COMMAND_MARKER", &marker)
        .output()
        .await
        .expect("witness command failed");
    let stdout = String::from_utf8_lossy(&output.stdout);
    println!(
        "shell_expanded_marker={}",
        usize::from(stdout.contains(&marker))
    );
}
