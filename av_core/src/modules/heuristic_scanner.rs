use crate::{
    core::scanner::{linux::file_struct_elf, shared::obfuscation, shared::strings},
    types::{FileData, HeuristicResult, HeuristicRule, Severity},
};

#[cfg(target_os = "windows")]
use crate::core::scanner::win::file_struct_exe;

pub struct SpireHeuristicEngine {
    rules: Vec<HeuristicRule>,
}

impl SpireHeuristicEngine {
    #[allow(clippy::new_without_default)]
    pub fn new() -> SpireHeuristicEngine {
        SpireHeuristicEngine {
            rules: vec![
                HeuristicRule {
                    name: "suspicious_strings",
                    description: "Поиск подозрительных команд в строках файла",
                    severity: Severity::High,
                    check_fn: strings::scan_suspicious_strings,
                },
                #[cfg(target_os = "windows")]
                HeuristicRule {
                    name: "pe_rwx_section",
                    description: "Проверка наличия RWX-секций в PE-файле",
                    severity: Severity::High,
                    check_fn: file_struct_exe::scan_pe_structure,
                },
                #[cfg(target_os = "linux")]
                HeuristicRule {
                    name: "elf_rwx_section",
                    description: "Проверка наличия RWX-секций в ELF-файле",
                    severity: Severity::High,
                    check_fn: file_struct_elf::scan_elf_structure,
                },
                HeuristicRule {
                    name: "xor_obfuscation",
                    description: "Obfuscation detection",
                    severity: Severity::Medium,
                    check_fn: obfuscation::detect_xor_obfuscation,
                },
            ],
        }
    }

    pub fn scan(&self, file_data: &FileData) -> HeuristicResult {
        let mut total_score = 0;
        let mut reasons = Vec::new();

        for rule in &self.rules {
            if let Some(reason) = (rule.check_fn)(file_data) {
                total_score += rule.severity.to_score();
                reasons.push(reason);
            }
        }

        if total_score >= 15 {
            HeuristicResult::Malicious {
                score: total_score,
                reason: reasons.join("; "),
            }
        } else if total_score >= 8 {
            HeuristicResult::Suspicious {
                score: total_score,
                reason: reasons.join("; "),
            }
        } else {
            HeuristicResult::Safe
        }
    }

    pub fn rules(&self) -> &[HeuristicRule] {
        &self.rules
    }
}
