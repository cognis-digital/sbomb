use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;

// CycloneDX 1.4 Schema Components
#[derive(Debug, Clone)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub type_: ComponentType,
    pub group: Option<String>,
    pub supplier: Option<Supplier>,
    pub scope: Scope,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ComponentType {
    Library,
    Application,
    Firmware,
    OperatingSystem,
    File,
    Other,
}

#[derive(Debug, Clone)]
pub struct Supplier {
    pub name: Option<String>,
    pub url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Scope {
    Required,
    Development,
    Optional,
}

impl Default for Component {
    fn default() -> Self {
        Component {
            name: String::new(),
            version: String::from("0.0.0"),
            type_: ComponentType::Library,
            group: None,
            supplier: None,
            scope: Scope::Required,
        }
    }
}

#[derive(Debug)]
pub struct SBOM {
    pub metadata: SBOMMetadata,
    pub components: Vec<Component>,
    pub dependencies: Vec<Dependency>,
    pub tools: Option<Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct SBOMMetadata {
    pub timestamp: String,
    pub manufacturer: Option<String>,
    pub supplier: Option<Supplier>,
    pub authors: Vec<String>,
    pub component: Option<Component>,
}

impl Default for SBOMMetadata {
    fn default() -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default();
        
        SBOMMetadata {
            timestamp: format!("{}Z", chrono::DateTime::from_timestamp(now.as_secs(), 0).unwrap().format("%Y-%m-%dT%H:%M:%S")),
            manufacturer: None,
            supplier: None,
            authors: vec!["sbomb".to_string()],
            component: Some(Component {
                name: "rootfs".to_string(),
                version: String::from("1.0"),
                type_: ComponentType::OperatingSystem,
                ..Default::default()
            }),
        }
    }
}

#[derive(Debug)]
pub struct Dependency {
    pub ref_: String,
    pub depends_on: Vec<String>,
}

// Known CVE database (sample entries - in production would load from file)
static KNOWN_CVES: Lazy<HashSet<(String, String)>> = Lazy::new(|| {
    let mut set = HashSet::new();
    
    // Example CVEs with affected versions
    set.insert(("glibc".to_string(), "2.17".to_string()));
    set.insert(("openssl".to_string(), "1.0.2".to_string()));
    set.insert(("zlib".to_string(), "1.2.3".to_string()));
    set.insert(("curl".to_string(), "7.46.0".to_string()));
    
    set
});

// EOL Kernel versions (sample - would load from file)
static EOL_KERNELS: Lazy<HashSet<String>> = Lazy::new(|| {
    let mut set = HashSet::new();
    set.insert("3.10");
    set.insert("4.4");
    set.insert("4.9");
    set.insert("5.4");
    set.insert("5.10");
    set
});

// ELF magic bytes for detection
const ELF_MAGIC: &[u8] = b"\x7fELF";
const PE_MAGIC: &[u8] = b"MZ";
const MACHO_MAGIC: &[u8] = b"\xfe\xef";

pub fn detect_binary_type(data: &[u8]) -> Option<BinaryType> {
    if data.len() < 4 {
        return None;
    }
    
    let header = &data[..std::cmp::min(4, data.len())];
    
    match header {
        ELF_MAGIC => Some(BinaryType::Elf),
        PE_MAGIC => Some(BinaryType::Pe),
        MACHO_MAGIC => Some(BinaryType::MachO),
        _ => None,
    }
}

pub enum BinaryType {
    Elf,
    Pe,
    MachO,
    Unknown,
}

pub fn extract_elf_version(data: &[u8]) -> Option<String> {
    if data.len() < 52 {
        return None;
    }
    
    let e_ident = &data[16..32];
    let ei_class = u8::from(e_ident[4]);
    let ei_data = u8::from(e_ident[5]);
    
    if ei_class != 2 || ei_data != 1 { // 64-bit, little endian
        return None;
    }
    
    let e_shoff = u32::from_le_bytes([data[40], data[41], data[42], data[43]]);
    let e_shentsize = u16::from_le_bytes([data[50], data[51]]);
    let e_shnum = u16::from_le_bytes([data[52], data[53]]);
    
    if e_shoff == 0 || e_shentsize == 0 {
        return None;
    }
    
    // Find .dynamic section for SONAME
    let mut found_soname = false;
    let mut version: Option<String> = None;
    
    for i in 0..e_shnum as usize {
        let sh_offset = e_shoff + (i as u32) * e_shentsize as u32;
        
        if sh_offset >= data.len() as u64 {
            break;
        }
        
        // Read section header entry
        let mut sh_name_offset: u32 = 0;
        let mut sh_type: u16 = 0;
        let mut sh_flags: u32 = 0;
        let mut sh_addr: u32 = 0;
        let mut sh_offset_u32: u32 = 0;
        let mut sh_size: u32 = 0;
        let mut sh_link: u16 = 0;
        let mut sh_info: u16 = 0;
        
        if e_shentsize as usize >= 64 {
            // 64-bit header
            sh_name_offset = u32::from_le_bytes([data[sh_offset as usize], data[sh_offset as usize + 1], data[sh_offset as usize + 2], data[sh_offset as usize + 3]]);
            sh_type = u16::from_le_bytes([data[sh_offset as usize + 4], data[sh_offset as usize + 5]]);
            sh_flags = u32::from_le_bytes([data[sh_offset as usize + 6], data[sh_offset as usize + 7], data[sh_offset as usize + 8], data[sh_offset as usize + 9]]);
            sh_addr = u32::from_le_bytes([data[sh_offset as usize + 10], data[sh_offset as usize + 11], data[sh_offset as usize + 12], data[sh_offset as usize + 13]]);
            sh_offset_u32 = u32::from_le_bytes([data[sh_offset as usize + 14], data[sh_offset as usize + 15], data[sh_offset as usize + 16], data[sh_offset as usize + 17]]);
            sh_size = u32::from_le_bytes([data[sh_offset as usize + 18], data[sh_offset as usize + 19], data[sh_offset as usize + 20], data[sh_offset as usize + 21]]);
            sh_link = u16::from_le_bytes([data[sh_offset as usize + 22], data[sh_offset as usize + 23]]);
            sh_info = u16::from_le_bytes([data[sh_offset as usize + 24], data[sh_offset as usize + 25]]);
        } else {
            // 32-bit header
            sh_name_offset = u32::from_le_bytes([data[sh_offset as usize], data[sh_offset as usize + 1], data[sh_offset as usize + 2], data[sh_offset as usize + 3]]);
            sh_type = u16::from_le_bytes([data[sh_offset as usize + 4], data[sh_offset as usize + 5]]);
            sh_flags = u32::from_le_bytes([data[sh_offset as usize + 6], data[sh_offset as usize + 7], data[sh_offset as usize + 8], data[sh_offset as usize + 9]]);
            sh_addr = u32::from_le_bytes([data[sh_offset as usize + 10], data[sh_offset as usize + 11], data[sh_offset as usize + 12], data[sh_offset as usize + 13]]);
            sh_offset_u32 = u32::from_le_bytes([data[sh_offset as usize + 14], data[sh_offset as usize + 15], data[sh_offset as usize + 16], data[sh_offset as usize + 17]]);
            sh_size = u32::from_le_bytes([data[sh_offset as usize + 18], data[sh_offset as usize + 19], data[sh_offset as usize + 20], data[sh_offset as usize + 21]]);
            sh_link = u16::from_le_bytes([data[sh_offset as usize + 22], data[sh_offset as usize + 23]]);
            sh_info = u16::from_le_bytes([data[sh_offset as usize + 24], data[sh_offset as usize + 25]]);
        }
        
        if sh_type == 0x11 { // DT_SONAME
            let name_start = (sh_offset_u32 as usize) + 1;
            let mut name_len = 0u8;
            
            for &b in data[name_start..].iter() {
                if b == 0 {
                    break;
                }
                name_len += 1;
            }
            
            if name_len > 0 && name_len < 256 {
                let soname = String::from_utf8_lossy(&data[name_start..name_start + name_len as usize]).to_string();
                
                // Extract version from SONAME (e.g., "libc.so.6" -> "6")
                if let Some(pos) = soname.rfind('.') {
                    let ver_str = &soname[pos + 1..];
                    if !ver_str.is_empty() && !ver_str.starts_with('_') {
                        version = Some(ver_str.to_string());
                        found_soname = true;
                    }
                }
            }
        } else if sh_type == 0x6 || sh_type == 0x7 { // DT_NEEDED or DT_NEEDED_64
            let name_start = (sh_offset_u32 as usize) + 1;
            let mut name_len = 0u8;
            
            for &b in data[name_start..].iter() {
                if b == 0 {
                    break;
                }
                name_len += 1;
            }
            
            if name_len > 0 && name_len < 256 {
                let needed = String::from_utf8_lossy(&data[name_start..name_start + name_len as usize]).to_string();
                
                // Extract version from library name (e.g., "libc.so.6" -> "6")
                if let Some(pos) = needed.rfind('.') {
                    let ver_str = &needed[pos + 1..];
                    if !ver_str.is_empty() && !ver_str.starts_with('_') {
                        version = Some(ver_str.to_string());
                        found_soname = true;
                    }
                }
            }
        }
        
        if found_soname {
            break;
        }
    }
    
    version
}

pub fn extract_pe_version(data: &[u8]) -> Option<String> {
    // PE header parsing would go here
    // For now, return a default based on common Windows libraries
    Some(String::from("0.0.0"))
}

pub fn scan_directory_for_binaries<P: AsRef<Path>>(root: P) -> Vec<BinaryInfo> {
    let root = root.as_ref();
    let mut binaries = Vec::new();
    
    // Collect all files first
    let entries: Vec<_> = WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .collect();
    
    for entry in entries {
        if entry.file_type().is_file() {
            let path = entry.path();
            
            // Skip very small files (likely not binaries)
            if entry.metadata().map_or(false, |m| m.len() < 64) {
                continue;
            }
            
            match fs::read(path) {
                Ok(data) => {
                    if let Some(binary_type) = detect_binary_type(&data) {
                        binaries.push(BinaryInfo {
                            path: path.to_path_buf(),
                            binary_type,
                            size: data.len() as u64,
                            version: extract_elf_version(&data).unwrap_or_else(|| "0.0.0".to_string()),
                        });
                    }
                }
                Err(_) => {}
            }
        }
    }
    
    binaries.sort_by(|a, b| a.path.cmp(&b.path));
    binaries
}

pub struct BinaryInfo {
    pub path: PathBuf,
    pub binary_type: BinaryType,
    pub size: u64,
    pub version: String,
}

pub fn scan_for_kernels<P: AsRef<Path>>(root: P) -> Vec<KernelInfo> {
    let root = root.as_ref();
    let mut kernels = Vec::new();
    
    // Common kernel header locations
    let search_paths = vec![
        "usr/src/linux-headers",
        "boot/vmlinux",
        "boot/Image",
        "boot/bzImage",
        "lib/modules/*/build/arch/x86/boot/vmlinux",
    ];
    
    for search_path in &search_paths {
        let full_path = root.join(search_path);
        
        if full_path.exists() && full_path.is_file() {
            match fs::read(&full_path) {
                Ok(data) => {
                    // Check ELF magic
                    if data.len() >= 4 && &data[0..4] == ELF_MAGIC {
                        let e_ident = &data[16..32];
                        let ei_class = u8::from(e_ident[4]);
                        
                        if ei_class == 2 { // 64-bit
                            let e_machine = u16::from_le_bytes([e_ident[10], e_ident[11]]);
                            
                            // x86_64 = 0x3E, x86 = 0x03
                            if e_machine == 0x3E || e_machine == 0x03 {
                                let mut version: Option<String> = None;
                                
                                // Try to extract kernel version from ELF notes or debug info
                                // For simplicity, use filename parsing
                                if let Some(filename) = full_path.file_name() {
                                    if let Some(name_str) = filename.to_str() {
                                        // Look for common patterns like "vmlinuz-5.10.0"
                                        if let Some(pos) = name_str.rfind('-') {
                                            let ver_part = &name_str[pos + 1..];
                                            if !ver_part.is_empty() && (ver_part.starts_with('0') || 
                                                                       ver_part.contains('.') ||
                                                                       ver_part.contains('_')) {
                                                version = Some(ver_part.to_string());
                                            }
                                        }
                                    }
                                }
                                
                                kernels.push(KernelInfo {
                                    path: full_path,
                                    architecture: if e_machine == 0x3E { "x86_64" } else { "x86" },
                                    version: version.unwrap_or_else(|| String::from("unknown")),
                                });
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
    }
    
    kernels.sort_by(|a, b| a.path.cmp(&b.path));
    kernels
}

pub struct KernelInfo {
    pub path: PathBuf,
    pub architecture: String,
    pub version: String,
}

pub fn check_eol_status(kernel: &KernelInfo) -> EOLStatus {