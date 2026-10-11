use crate::types::{FileContainer, FileData};
use goblin::elf;

#[cfg(target_os = "linux")]
pub fn scan_elf_structure(data: &FileData) -> Option<String> {
    let elf = match &data.container {
        FileContainer::Elf(elf) => elf,
        _ => return None,
    };

    for ph in &elf.program_headers {
        let flags = ph.p_flags;
        let is_read = flags & elf::program_header::PF_R != 0;
        let is_write = flags & elf::program_header::PF_W != 0;
        let is_exec = flags & elf::program_header::PF_X != 0;

        if is_read && is_write && is_exec {
            return Some("Detected segment with RWX permissions (read+write+execute)".to_string());
        }
    }

    if let Some(interp) = elf.interpreter {
        let common_interp = [
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/usr/lib64/ld-linux-x86-64.so.2",
            "/lib/ld-linux-armhf.so.3",
        ];
        if !common_interp.iter().any(|&s| interp.contains(s)) {
            return Some(format!("Suspicious interpreter: {}", interp));
        }
    }

    let suspicious_libs = [
        "libsystemd.so",
        "libdl.so",
        "libpthread.so",
        "libm.so",
        "libncurses.so",
    ];

    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == elf::dynamic::DT_NEEDED
                && let Some(name) = elf.strtab.get_at(dyn_entry.d_val as usize)
                && suspicious_libs.iter().any(|&s| name.contains(s))
            {
                return Some(format!("Suspicious library in DT_NEEDED: {}", name));
            }
        }
    }

    for sh in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name)
            && (name.starts_with(".gob") || name.starts_with(".crypt") || name.starts_with(".xor"))
        {
            return Some(format!("Detected suspicious section: {}", name));
        }
    }

    if data.bytes.len() > 5 * 1024 * 1024 {
        return Some("File is very large (>5MB), may contain embedded shellcode".to_string());
    }

    None
}
