use std::collections::{HashMap, HashSet};
use std::fs::{self, File, DirEntry};
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use sha2::{Sha256, Digest};

/// Magic number signatures for common binary formats.
pub struct FileMagic {
    pub elf: [u8; 4],
    pub pe: [u8; 4],
    pub mach_o: [u8; 4],
    pub iso9660: [u8; 4],
}

impl FileMagic {
    const fn new() -> Self {
        Self {
            elf: *b"\x7fELF",
            pe: *b"MZ",
            mach_o: *b"!\x03\x00\x00",
            iso9660: *b"ISO9660",
        }
    }

    pub fn detect(&self, data: &[u8]) -> Option<BinaryFormat> {
        if data.len() < 4 {
            return None;
        }

        let header = &data[0..4];

        match header {
            b"\x7fELF" => Some(BinaryFormat::Elf),
            b"MZ" => Some(BinaryFormat::PeCoff),
            b"!\x03\x00\x00" | b"!\x02\x00\x00" | b"!\x01\x00\x00" => {
                // Mach-O variants (64-bit, 32-bit, fat)
                Some(BinaryFormat::MachO)
            }
            _ if header == &self.iso9660[..] => Some(BinaryFormat::Iso9660),
            _ => None,
        }
    }
}

/// Supported binary formats.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinaryFormat {
    Elf,
    PeCoff,
    MachO,
    Iso9660,
    Unknown,
}

impl std::fmt::Display for BinaryFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Elf => write!(f, "ELF"),
            Self::PeCoff => write!(f, "PE/COFF (Windows)"),
            Self::MachO => write!(f, "Mach-O (macOS/iOS)"),
            Self::Iso9660 => write!(f, "ISO 9660 CD-ROM"),
            Self::Unknown => write!(f, "Unknown/Other"),
        }
    }
}

/// Known ELF headers for Linux distributions.
pub struct ElfHeaderInfo {
    pub class: u8, // 1=32-bit, 2=64-bit
    pub endian: u8, // 1=little, 2=big
    pub version: u8,
    pub abi_major: u8,
    pub abi_minor: u8,
}

impl ElfHeaderInfo {
    const fn new(data: &[u8]) -> Option<Self> {
        if data.len() < 64 {
            return None;
        }

        // ELF header at offset 0
        let class = data[4];
        let endian = data[5];
        let version = data[6];
        let abi_major = data[12];
        let abi_minor = data[13];

        if class == 2 && (endian & 1) == 0 {
            // 64-bit little-endian
            return Some(Self {
                class,
                endian,
                version,
                abi_major,
                abi_minor,
            });
        } else if class == 1 && (endian & 1) != 0 {
            // 32-bit big-endian
            return Some(Self {
                class,
                endian,
                version,
                abi_major,
                abi_minor,
            });
        }

        None
    }
}

/// Result of binary identification.
#[derive(Debug, Clone)]
pub struct BinaryIdentifyResult {
    pub path: PathBuf,
    pub format: BinaryFormat,
    pub sha256: String,
    pub md5: String,
    pub size_bytes: u64,
    pub mtime: SystemTime,
    pub elf_info: Option<ElfHeaderInfo>,
    pub candidates: Vec<String>, // Possible binary names (e.g., "libc.so.6")
}

impl BinaryIdentifyResult {
    pub fn new(path: PathBuf) -> Self {
        let mut file = match File::open(&path) {
            Ok(f) => f,
            Err(_) => return Self {
                path,
                format: BinaryFormat::Unknown,
                sha256: String::new(),
                md5: String::new(),
                size_bytes: 0,
                mtime: SystemTime::now(),
                elf_info: None,
                candidates: Vec::new(),
            },
        };

        let mut buffer = [0u8; 1024];
        if file.read(&mut buffer).is_err() {
            return Self {
                path,
                format: BinaryFormat::Unknown,
                sha256: String::new(),
                md5: String::new(),
                size_bytes: 0,
                mtime: SystemTime::now(),
                elf_info: None,
                candidates: Vec::new(),
            };
        }

        let format = FileMagic::new().detect(&buffer);
        
        // Compute hashes
        let mut hasher_sha256 = Sha256::new();
        let mut hasher_md5 = md5::Md5::new();
        file.seek(SeekFrom::Start(0)).unwrap_or(());
        file.read_to_end(&mut hasher_sha256).unwrap_or(());
        file.seek(SeekFrom::Start(0)).unwrap_or(());
        file.read_to_end(&mut hasher_md5).unwrap_or(());

        let sha256 = format!("{:x}", hasher_sha256.finalize());
        let md5 = format!("{:x}", hasher_md5.compute());

        // Extract ELF info if applicable
        let elf_info = if matches!(format, BinaryFormat::Elf) {
            ElfHeaderInfo::new(&buffer).cloned()
        } else {
            None
        };

        Self {
            path,
            format: format.unwrap_or(BinaryFormat::Unknown),
            sha256,
            md5,
            size_bytes: file.metadata().map(|m| m.len()).unwrap_or(0),
            mtime: file.metadata().and_then(|m| m.modified()).unwrap_or(SystemTime::now()),
            elf_info,
            candidates: Vec::new(),
        }
    }

    /// Match against known binaries database.
    pub fn match_known_binaries(&self) -> Vec<String> {
        let mut matches = Vec::new();

        // Check ELF dynamic linker hints (common in embedded firmware)
        if matches!(self.format, BinaryFormat::Elf) {
            // Look for common libc.so.* patterns by hash
            let known_libc_hashes: &[(&str, &str)] = &[
                ("libc.so.6", "a1f2b3c4d5e6"), // Example placeholder
                ("libm.so.6", "b2c3d4e5f6a7"),
            ];

            for (name, expected_hash) in known_libc_hashes.iter() {
                if self.md5.as_str().starts_with(expected_hash.chars().next().unwrap_or('0')) {
                    matches.push(name.to_string());
                }
            }
        }

        // Check for common embedded firmware binaries by signature
        let firmware_signatures: &[(&str, &[u8])] = &[
            ("busybox", b"\x27\x45\x4f\x10"), // BusyBox magic
            ("uClibc", b"uClibc"),
            ("musl libc", b"musl"),
        ];

        for (name, sig) in firmware_signatures.iter() {
            if self.path.extension().map(|e| e.to_string_lossy()).unwrap_or_default() == "elf" {
                let header = &self.path.metadata().and_then(|m| m.file_name())
                    .map(|n| n.to_string_lossy());

                if let Some(h) = header.as_deref() {
                    if h.contains(name) || self.sha256.len() > 0 && 
                       self.sha256.starts_with(&format!("{:x}", Digest::digest(Sha256::new_from_slice(sig).unwrap()))) {
                        matches.push(format!("{} (firmware)", name));
                    }
                }
            }
        }

        // Default candidate if format detected but not matched
        match self.format {
            BinaryFormat::Elf => {
                let arch = if self.elf_info.as_ref().map(|i| i.class == 2).unwrap_or(false) {
                    "x86_64"
                } else {
                    "x86"
                };
                matches.push(format!("{} ELF binary (arch: {})", 
                    self.format, arch));
            }
            BinaryFormat::PeCoff => {
                matches.push("Windows PE executable".to_string());
            }
            _ => {}
        }

        matches
    }

    pub fn is_kernel(&self) -> bool {
        if let Some(ref info) = self.elf_info {
            // Check for kernel-like ABI versioning (Linux 5.x+)
            if info.abi_major >= 5 && info.abi_minor > 0 {
                return true;
            }
        }
        
        // Check filename patterns
        let name_lower = self.path.file_name()
            .and_then(|n| n.to_string_lossy().to_lowercase());

        matches!(name_lower.as_deref(), 
            Some("vmlinuz") | Some("bzImage") | Some("initramfs") | 
            Some("System.map") | Some("config") | Some("defconfig"))
    }
}

/// Configuration for binary identification.
#[derive(Debug, Clone)]
pub struct IdentifyConfig {
    pub min_size: u64,           // Minimum file size to process (default 512 bytes)
    pub max_depth: u32,          // Maximum directory depth (default 10)
    pub include_hidden: bool,    // Include .hidden files/dirs (default true)
    pub follow_symlinks: bool,   // Follow symlinks (default false)
}

impl Default for IdentifyConfig {
    fn default() -> Self {
        Self {
            min_size: 512,
            max_depth: 10,
            include_hidden: true,
            follow_symlinks: false,
        }
    }
}

/// Scan a directory tree and identify all binaries.
pub fn scan_directory<P: AsRef<Path>>(
    root: P,
    config: &IdentifyConfig,
) -> Result<Vec<BinaryIdentifyResult>, std::io::Error> {
    let mut results = Vec::new();

    let walker = fs::WalkDir::new(root.as_ref())
        .min_depth(0)
        .max_depth(config.max_depth as usize)
        .follow_links(config.follow_symlinks)
        .sort_by_filename()
        .into_iter()
        .filter_map(|e| e.ok());

    for entry in walker {
        let path = entry.path();
        
        // Skip non-regular files and very small ones
        if !path.is_file() || path.metadata().map(|m| m.len()).unwrap_or(0) < config.min_size {
            continue;
        }

        // Include hidden by default (config controls this)
        let name = path.file_name();
        if let Some(n) = name {
            if !config.include_hidden && n.to_string_lossy().starts_with('.') {
                continue;
            }
        }

        results.push(BinaryIdentifyResult::new(path.clone()));
    }

    Ok(results)
}

/// Generate a summary report of identified binaries.
pub fn generate_report(
    results: &[BinaryIdentifyResult],
    output_format: ReportFormat,
) -> String {
    let mut buf = String::new();

    match output_format {
        ReportFormat::Json => {
            buf.push_str(r#"{
  "scan_summary": {
    "total_files": {},
    "by_format": {},
    "kernels_detected": [],
    "unknown_formats": []
  },
  "files": [
"#;

            let mut by_format: HashMap<BinaryFormat, u64> = HashMap::new();
            let mut kernels: Vec<&BinaryIdentifyResult> = Vec::new();
            let mut unknown: Vec<&BinaryIdentifyResult> = Vec::new();

            for r in results {
                *by_format.entry(r.format).or_insert(0) += 1;
                
                if r.is_kernel() {
                    kernels.push(r);
                } else if matches!(r.format, BinaryFormat::Unknown) {
                    unknown.push(r);
                }

                buf.push_str(&format!(r#"{{"path": "{}", "format": "{:?}","sha256": "{}", "size_bytes": {}, "is_kernel": {}},
"#, 
                    r.path.to_string_lossy(),
                    r.format,
                    r.sha256,
                    r.size_bytes,
                    if r.is_kernel() { true } else { false },
                ));
            }

            buf.pop(); // Remove trailing comma
            buf.push_str(r#"]
}"#);
        }
        ReportFormat::Text => {
            let mut by_format: HashMap<BinaryFormat, u64> = HashMap::new();
            
            for r in results {
                *by_format.entry(r.format).or_insert(0) += 1;

                buf.push_str(&format!(
                    "Path: {:50} | Format: {:20} | Size: {:8} bytes\n",
                    r.path.to_string_lossy(),
                    r.format,
                    r.size_bytes
                ));

                if let Some(ref info) = r.elf_info {
                    buf.push_str(&format!(
                        "  ELF Class: {}, ABI: {}.{}.{}\n",
                        match info.class { 1 => "32-bit", 2 => "64-bit" },
                        info.abi_major, info.abi_minor, info.abi_minor % 10
                    ));
                }

                if r.is_kernel() {
                    buf.push_str("  *** KERNEL DETECTED ***\n");
                }
            }

            // Summary
            let total: u64 = by_format.values().sum();
            buf.push_str(&format!(
                "\n\n=== SUMMARY ===\nTotal files: {}\nBy format:\n",
                total
            ));

            for (fmt, count) in &by_format {
                buf.push_str(&format!("  {:15}: {}\n", fmt, count));
            }
        }
    }

    buf
}

/// Output format for reports.
#[derive(Debug, Clone, Copy)]
pub enum ReportFormat {
    Json,
    Text,
}

impl Default for ReportFormat {
    fn default() -> Self {
        Self::Text
    }
}

/// Main entry point for binary identification.
pub struct BinaryIdentifier {
    config: IdentifyConfig,
    output_format: ReportFormat,
}

impl Default for BinaryIdentifier {
    fn default() -> Self {
        Self {
            config: IdentifyConfig::default(),
            output_format: ReportFormat::Text,
        }
    }
}

impl BinaryIdentifier {
    pub fn new(config: Option<IdentifyConfig>, format: Option<ReportFormat>) -> Self {
        let cfg = config.unwrap_or_default();
        let fmt = format.unwrap_or(ReportFormat::default());
        Self { config: cfg, output_format: fmt }
    }

    /// Perform identification on a directory.
    pub fn identify<P: AsRef<Path>>(&self, root: P) -> Result<String, std::io::Error> {
        let results = scan_directory(root.as_ref(), &self.config)?;
        
        if results.is_empty() {
            return Ok(format!("No files found in {}", root.as_ref().display()));
        }

        generate_report(&results, self.output_format)
    }

    /// Identify a single file.
    pub fn identify_file<P: AsRef<Path>>(&self, path: P) -> Result<String, std::io::Error> {
        let result = BinaryIdentifyResult::new(path.as_ref());
        
        if matches!(result.format, BinaryFormat::Unknown) {
            return Ok(format!("Failed to read file or unknown format"));
        }