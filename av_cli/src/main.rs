use av_engine::AvEngine;
use clap::Parser;
use env_logger::Builder;
use indicatif::MultiProgress;
// use sysinfo::System;

use cli::commands::{Cli, Command};
use log::LevelFilter;

mod cli;
// mod generated;

fn main() -> anyhow::Result<()> {
    let args = Cli::parse();

    let log_level = match args.verbose {
        0 => LevelFilter::Info,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Debug,
    };

    Builder::new().filter_level(log_level).init();

    log::debug!("Apps run in: {:?} mode", log_level);

    let m = MultiProgress::new();

    match args.command {
        Command::CheckFeed => {
            let cfg = av_core::core::config::Config::load()?;
            let key = cfg
                .update_public_key
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("Configure update_public_key"))?;
            let feed = av_core::core::updates::active(&cfg.spire_dir(), key)?
                .ok_or_else(|| anyhow::anyhow!("No installed feed"))?;
            println!("Verified feed version {}", feed.version);
        }
        Command::Scan {
            scan_type,
            quarantine,
        } => AvEngine::new()?.scan(
            scan_type,
            &m,
            if quarantine {
                av_core::core::response::ResponsePolicy::Quarantine
            } else {
                av_core::core::response::ResponsePolicy::Observe
            },
        )?,
        Command::Config { action } => {
            dbg!(action);
            unimplemented!("Not yet working");
        }
        Command::Quarantine { action } => AvEngine::quarantine(action)?,
        Command::PasswordManager { action } => unimplemented!("Not yet working {action:?}"),
        Command::UpdateDB { url } => AvEngine::update(url)?,
    }

    Ok(())
}
