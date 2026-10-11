use clap::{Parser, Subcommand};

use av_core::types::{OnDemaindScanModes, QuarantineAction};

#[derive(Parser, Debug)]
#[command(
    version = "0.2.0",
    name = "Rust Sentinel",
    about = "Simple rust AntiVirus"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
    #[clap(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Verify the installed feed without scanning files or contacting the server.
    CheckFeed,
    Scan {
        /// Apply quarantine explicitly; default is detection only.
        #[arg(long)]
        quarantine: bool,
        #[clap(subcommand)]
        scan_type: OnDemaindScanModes,
    },
    Quarantine {
        #[clap(subcommand)]
        action: QuarantineAction,
    },
    Config {
        #[clap(subcommand)]
        action: QuarantineAction,
    },
    #[command(name = "update-db")]
    UpdateDB {
        #[arg(long)]
        url: Option<String>,
    },
    PasswordManager {
        #[clap(subcommand)]
        action: PasswordManagerAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum PasswordManagerAction {
    List,
    Add,
    Remove { id: String },
}
