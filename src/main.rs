//! `pwsafe` — a Windows DPAPI-backed CLI password safe. This file only wires
//! up the command line; the actual behavior lives in the other modules.

#[cfg(not(windows))]
compile_error!("pwsafe requires Windows: secrets are protected by the Windows DPAPI");

mod clipboard;
mod commands;
mod dpapi;
mod output;
mod password;
mod prompt;
mod vault;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

use crate::clipboard::DEFAULT_CLEAR_SECS;
use crate::output::problem;
use crate::password::DEFAULT_LENGTH;

const KEY_HELP: &str = "Identifier for the credential (1-128 printable ASCII chars), e.g. github";

#[derive(Args)]
struct ClearSecs {
    #[arg(
        long,
        default_value_t = DEFAULT_CLEAR_SECS,
        value_name = "SECS",
        help = "Seconds before the clipboard is wiped if unchanged (0 disables)"
    )]
    clear_secs: u64,
}

#[derive(Parser)]
#[command(
    name = "pwsafe",
    version,
    about = "CLI password safe secured by Windows DPAPI (CurrentUser)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(about = "Generate a password, store it under KEY, and copy it to the clipboard")]
    Add {
        #[arg(help = KEY_HELP)]
        key: String,
        #[arg(short, long, default_value_t = DEFAULT_LENGTH, help = "Password length (8-256)")]
        length: usize,
        #[arg(long, help = "Overwrite an existing entry")]
        force: bool,
        #[command(flatten)]
        clear: ClearSecs,
    },
    #[command(about = "Store an existing password for KEY (hidden prompt, or one line on stdin)")]
    Set {
        #[arg(help = KEY_HELP)]
        key: String,
        #[arg(long, help = "Overwrite an existing entry")]
        force: bool,
    },
    #[command(about = "Copy the password for KEY to the clipboard")]
    Get {
        #[arg(help = KEY_HELP)]
        key: String,
        #[command(flatten)]
        clear: ClearSecs,
    },
    #[command(about = "List stored keys (never prints secrets)")]
    List,
    #[command(about = "Delete KEY from the vault")]
    Rm {
        #[arg(help = KEY_HELP)]
        key: String,
    },
}

fn main() {
    if let Err(err) = run() {
        problem!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    match Cli::parse().command {
        Command::Add {
            key,
            length,
            force,
            clear,
        } => commands::add(&key, length, force, clear.clear_secs),
        Command::Set { key, force } => commands::set(&key, force),
        Command::Get { key, clear } => commands::get(&key, clear.clear_secs),
        Command::List => commands::list(),
        Command::Rm { key } => commands::rm(&key),
    }
}
