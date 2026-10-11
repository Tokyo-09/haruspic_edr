use crate::types::{FileContainer, FileData};
use goblin::elf;

#[cfg(target_os = "windows")]
use goblin::pe;

#[cfg(target_os = "windows")]
pub fn scan_pe_structure(data: &FileData) -> Option<String> {
    let pe = match &data.container {
        FileContainer::Pe(pe) => pe,
        _ => return None,
    };

    for section in &pe.sections {
        let characteristics = section.characteristics;
        if characteristics & pe::section_table::IMAGE_SCN_MEM_READ != 0
            && characteristics & pe::section_table::IMAGE_SCN_MEM_WRITE != 0
            && characteristics & pe::section_table::IMAGE_SCN_MEM_EXECUTE != 0
        {
            return Some("Detected section with RWX permissions (read+write+execute)".to_string());
        }
    }

    let suspicious_imports = [
        "VirtualAlloc",
        "WriteProcessMemory",
        "CreateRemoteThread",
        "ShellExecute",
        "WinExec",
        "LoadLibrary",
        "GetProcAddress",
    ];

    for import in &pe.imports {
        let name = import.name.clone();
        if suspicious_imports.iter().any(|&s| name.contains(s)) {
            return Some(format!("Suspicious import: {}", name));
        }
    }

    None
}
