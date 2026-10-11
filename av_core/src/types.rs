use goblin::{elf::Elf, mach::MachO, pe::PE};
use std::path::PathBuf;

#[derive(clap::Subcommand, Debug)]
pub enum QuarantineAction {
    // List quarantined files
    List {},
    // Restore quarantined files
    Restore {
        #[clap(long, value_parser)]
        id: i64,
    },
    // Delete quarantined files
    Delete {
        #[clap(long, value_parser)]
        id: i64,
    },
}

#[derive(clap::Subcommand)]
pub enum ConfigAction {
    List {},
    Add {
        exclude_dir: Option<PathBuf>,

        exclude_extensions: Option<Vec<String>>,

        exclude_processes: Option<Vec<String>>,
    },
    Delete {
        rule_id: Option<i64>,
    },
}

pub enum ScanModes {
    Monitor,
    OnDemaindScanModes,
}

pub enum Monitor {
    SystemMonitor { path: PathBuf },
}

#[derive(clap::Subcommand, Debug)]
pub enum OnDemaindScanModes {
    Fast {
        // Directory or file to scan
        #[arg(long)]
        path: PathBuf,
        // Generate report
        #[arg(long)]
        report: Option<PathBuf>,
    },
    Full {
        //Path with yara rules
        #[arg(long, value_parser)]
        rules: Option<PathBuf>,
        //Path to scan
        #[arg(long)]
        path: PathBuf,
        // Report
        #[clap(long, value_parser)]
        report: Option<PathBuf>,
    },
    YaraScan {
        // Path with yara rules
        #[arg(long, value_parser)]
        rules: Option<PathBuf>,

        //Path to scan
        #[arg(long)]
        path: PathBuf,
        // Report
        #[clap(long, value_parser)]
        report: Option<PathBuf>,
    },
    ProcessScan {},
}

#[derive(Debug, Clone, PartialEq)]
pub enum HeuristicResult {
    Safe,
    Suspicious { score: u8, reason: String },
    Malicious { score: u8, reason: String },
}

#[derive(Debug, Clone)]
pub struct HeuristicRule {
    pub name: &'static str,
    pub description: &'static str,
    pub severity: Severity,
    pub check_fn: fn(&FileData) -> Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl Severity {
    pub fn to_score(&self) -> u8 {
        match self {
            Severity::Low => 2,
            Severity::Medium => 5,
            Severity::High => 8,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum FileType {
    PE,
    ELF,
    MachO,
    Script,
    Unknown,
}

#[derive(Debug)]
pub enum FileContainer<'a> {
    Elf(Box<Elf<'a>>),
    Pe(Box<PE<'a>>),
    MachO(Box<MachO<'a>>),
    None,
}

#[derive(Debug)]
pub struct FileData<'a> {
    pub bytes: Vec<u8>,
    pub file_type: FileType,
    pub strings: Vec<String>,
    pub container: FileContainer<'a>,
}
