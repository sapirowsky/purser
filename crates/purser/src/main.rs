//! purser — one-command dev-environment sync with agent-blind secrets.
//!
//! This is a scaffold: it prints help and holds the crates.io name. Real commands
//! land as the workspace crates fill in. Design lives in the `futureos` planning repo.

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        // Easter egg. Non-negotiable brand rule: "Rust good" appears somewhere. 🦀
        Some("rust") => println!("good."),
        Some("--version") | Some("-V") => {
            println!("purser {VERSION}");
            println!("built with Rust. Rust good. 🦀");
        }
        _ => print_help(),
    }
}

fn print_help() {
    println!("purser {VERSION} — dev-environment sync + agent-blind secrets");
    println!();
    println!("USAGE:");
    println!("  purser up                 reproduce this machine (clone, install, inject env)");
    println!("  purser import .env         encrypt secrets, remove the plaintext .env");
    println!("  purser agent -- <cmd>      run an agent that can't see secret values");
    println!("  purser run -- <cmd>        run with secrets injected in memory only");
    println!("  purser audit last          show the last session receipt");
    println!("  purser device pair         enroll another of your own devices (p2p)");
    println!();
    println!("  (scaffold — commands not implemented yet.)");
    println!();
    println!("built with Rust. Rust good. 🦀");
}
