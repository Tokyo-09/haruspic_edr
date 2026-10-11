use clap::Parser;

#[derive(Parser, Debug)]
#[command(version, about = "Filesystem monitoring utility", long_about = None)]
pub struct Cli {
    #[clap(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}
