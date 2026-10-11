pub mod yara {
    use std::path::PathBuf;
    use yara_x::{Compiler, Rules};

    pub fn compile_yara_rules(rules_path: &PathBuf) -> anyhow::Result<Rules> {
        use crate::core::limits::read_bounded;
        use std::time::{Duration, Instant};
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut compiler = Compiler::new();
        // Includes could read outside the verified feed; each rule file is explicit.
        compiler.enable_includes(false);
        let mut count = 0;
        let mut total = 0;
        for (index, entry) in walkdir::WalkDir::new(rules_path)
            .follow_links(false)
            .max_open(16)
            .sort_by_file_name()
            .into_iter()
            .enumerate()
        {
            anyhow::ensure!(
                index < 4096 && Instant::now() < deadline,
                "YARA rule compilation budget exceeded"
            );
            let entry = entry?;
            anyhow::ensure!(
                !entry.file_type().is_symlink(),
                "YARA symlinks are forbidden"
            );
            if !entry.file_type().is_file() {
                continue;
            }
            if !matches!(
                entry.path().extension().and_then(|s| s.to_str()),
                Some("yar" | "yara")
            ) {
                continue;
            }
            let bytes = read_bounded(entry.path(), 1024 * 1024, deadline)?;
            total += bytes.len();
            anyhow::ensure!(total <= 16 * 1024 * 1024, "YARA source budget exceeded");
            compiler
                .add_source(bytes.as_slice())
                .map_err(|e| anyhow::anyhow!("{}: {e}", entry.path().display()))?;
            count += 1;
        }
        anyhow::ensure!(count > 0, "No YARA sources found");
        Ok(compiler.build())
    }
}

pub mod heuristic_analyze {
    use crate::types::{FileContainer, FileData, FileType};
    use goblin::{elf::Elf, mach::MachO, pe::PE};

    pub fn parse_file<'a>(bytes: &'a [u8]) -> Result<FileData<'a>, Box<dyn std::error::Error>> {
        let (file_type, container) = if bytes.len() >= 4 && &bytes[0..4] == b"\x7FELF" {
            let elf = Elf::parse(bytes)?;
            (FileType::ELF, FileContainer::Elf(Box::new(elf)))
        } else if bytes.len() >= 2 && &bytes[0..2] == b"MZ" {
            let pe = PE::parse(bytes)?;
            (FileType::PE, FileContainer::Pe(Box::new(pe)))
        } else if bytes.len() >= 4
            && (&bytes[0..4] == b"\xFE\xED\xFA\xCE" || &bytes[0..4] == b"\xCE\xFA\xED\xFE")
        {
            let macho = MachO::parse(bytes, 0)?;
            (FileType::MachO, FileContainer::MachO(Box::new(macho)))
        } else {
            (FileType::Unknown, FileContainer::None)
        };

        let strings = extract_ascii_strings(bytes, 4);

        Ok(FileData {
            bytes: bytes.to_vec(),
            file_type,
            strings,
            container,
        })
    }

    pub fn extract_ascii_strings(bytes: &[u8], min_len: usize) -> Vec<String> {
        let mut strings = Vec::new();
        let mut current = Vec::new();

        for &b in bytes {
            if b.is_ascii_graphic() || b == b' ' || b == b'\t' {
                current.push(b);
            } else {
                if current.len() >= min_len
                    && let Ok(s) = String::from_utf8(current.clone())
                {
                    strings.push(s);
                }

                current.clear();
            }
        }

        if current.len() >= min_len
            && let Ok(s) = String::from_utf8(current)
        {
            strings.push(s);
        }

        strings
    }
}

pub mod scanner {
    use indicatif::{ProgressBar, ProgressStyle};

    pub fn create_progress_bar(total: u64, message: &str) -> anyhow::Result<ProgressBar> {
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")?
                .progress_chars("#>-"),
        );
        pb.set_message(message.to_string());
        Ok(pb)
    }
}
