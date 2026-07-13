"""
polyglot/python/binary_identification.py

Binary identification and analysis for SBOM generation from unpacked firmware.
Detects file types, architectures, extracts libraries, and flags known CVEs/EOL kernels.
"""

import os
import struct
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple, BinaryIO


@dataclass
class ArchitectureInfo:
    name: str = "Unknown"
    bits: int = 0
    endian: str = "?"
    
    def __str__(self) -> str:
        return f"{self.name} ({self.bits}-bit, {self.endian})"


@dataclass
class BinaryInfo:
    path: Path
    name: str
    size: int
    arch: ArchitectureInfo
    type_name: str = "Unknown"
    libraries: List[str] = field(default_factory=list)
    symbols: Dict[str, Any] = field(default_factory=dict)
    debug_info: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        return f"{self.name} ({self.arch})"


@dataclass
class CVEFlag:
    cve_id: str
    severity: str = "Unknown"
    cvss_score: float = 0.0
    description: str = ""
    
    def __str__(self) -> str:
        return f"{self.cve_id} [{self.severity}] {self.cvss_score}"


@dataclass
class EOLFlag:
    component: str
    version: str
    eol_date: Optional[datetime] = None
    source: str = ""
    
    def __str__(self) -> str:
        return f"{self.component} {self.version} (EOL)"


@dataclass
class AnalysisResult:
    binaries: List[BinaryInfo] = field(default_factory=list)
    cve_flags: List[CVEFlag] = field(default_factory=list)
    eol_flags: List[EOLFlag] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


class BinaryIdentifier:
    """Identifies and analyzes binaries in firmware filesystems."""
    
    # ELF magic numbers
    ELF_MAGIC = b'\x7fELF'
    ELF32_CLASS = 1
    ELF64_CLASS = 2
    
    # PE/COFF magic
    PE_MAGIC = 0x00004550  # "PE\0\0"
    
    # Mach-O magic
    MACHO_MAGIC_64 = 0xFEEDFACE
    MACHO_MAGIC_32 = 0xFEEDFACF
    
    def __init__(self, cache_dir: Optional[Path] = None):
        self.cache_dir = Path(cache_dir) if cache_dir else Path.home() / ".sbomb" / "cache"
        self._ensure_cache()
    
    def _ensure_cache(self) -> None:
        """Ensure cache directory exists."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
    
    def identify_file(self, path: Path) -> BinaryInfo:
        """Identify a single binary file."""
        if not path.is_file():
            return BinaryInfo(path=path, name="unknown", size=0, arch=ArchitectureInfo())
        
        try:
            with open(path, 'rb') as f:
                magic = f.read(16)
                header_size = min(len(magic), 52)  # Read enough for most formats
                
                info = self._analyze_header(magic, path)
                
                if info.type_name == "ELF":
                    info.libraries, info.symbols = self._parse_elf(path)
                elif info.type_name == "PE":
                    pass  # PE parsing is more complex, optional
                elif info.type_name == "Mach-O":
                    pass
                
                return info
                
        except (IOError, struct.error):
            return BinaryInfo(
                path=path, 
                name="unknown", 
                size=path.stat().st_size if path.is_file() else 0,
                arch=ArchitectureInfo(),
                type_name="Unknown"
            )
    
    def _analyze_header(self, magic: bytes, path: Path) -> BinaryInfo:
        """Analyze file header to determine format and architecture."""
        size = path.stat().st_size if path.is_file() else 0
        
        # ELF detection
        if magic[:4] == self.ELF_MAGIC:
            elf_class = magic[4]
            endian = magic[5]
            
            arch_info = ArchitectureInfo(
                name="x86_64" if endian == 2 and elf_class == self.ELF64_CLASS else 
                       "x86" if endian == 1 and elf_class == self.ELF32_CLASS else
                       "ARM" if endian in (1, 2) and elf_class == self.ELF32_CLASS else
                       "Unknown",
                bits=64 if elf_class == self.ELF64_CLASS else 32,
                endian="Little" if endian == 1 else ("Big" if endian == 2 else "?")
            )
            
            # Check for common ELF architectures
            if endian == 2 and elf_class == self.ELF64_CLASS:
                arch_info.name = "x86_64"
            elif endian == 1 and elf_class == self.ELF32_CLASS:
                arch_info.name = "i386"
            elif endian in (1, 2) and elf_class == self.ELF32_CLASS:
                # Could be ARM, MIPS, etc. - need more analysis
                arch_info.name = "ARM" if b'\x01' in magic[:4] else "Unknown"
            
            return BinaryInfo(
                path=path, name=path.name, size=size, 
                arch=arch_info, type_name="ELF"
            )
        
        # PE detection (Windows executables)
        elif struct.unpack('<I', magic[2:6]) == self.PE_MAGIC:
            return BinaryInfo(
                path=path, name=path.name, size=size,
                arch=ArchitectureInfo(name="PE", bits=32),
                type_name="PE"
            )
        
        # Mach-O detection (macOS/iOS)
        elif magic[:4] == struct.pack('<I', self.MACHO_MAGIC_64):
            return BinaryInfo(
                path=path, name=path.name, size=size,
                arch=ArchitectureInfo(name="Mach-O 64", bits=64),
                type_name="Mach-O"
            )
        
        # Assume text executable if it looks like code
        elif self._looks_like_text(magic):
            return BinaryInfo(
                path=path, name=path.name, size=size,
                arch=ArchitectureInfo(name="Text/Script", bits=0),
                type_name="Text"
            )
        
        # Unknown binary
        else:
            return BinaryInfo(
                path=path, name=path.name, size=size,
                arch=ArchitectureInfo(),
                type_name="Unknown"
            )
    
    def _looks_like_text(self, magic: bytes) -> bool:
        """Quick heuristic for text/script files."""
        try:
            decoded = magic.decode('utf-8', errors='ignore')
            # Check for common script shebangs or keywords
            if any(s in decoded.lower() for s in ['#!/bin/', 'python ', '#!', 'def ', 'class ']):
                return True
        except:
            pass
        return False
    
    def _parse_elf(self, path: Path) -> Tuple[List[str], Dict[str, Any]]:
        """Parse ELF file to extract libraries and symbols."""
        libraries = []
        symbols = {}
        
        try:
            with open(path, 'rb') as f:
                # Read ELF header
                magic = f.read(16)
                
                if magic[:4] != self.ELF_MAGIC:
                    return libraries, symbols
                
                # Parse ELF header fields
                ei_class = struct.unpack('B', magic[4:5])[0]
                ei_data = struct.unpack('B', magic[5:6])[0]  # Endian flag
                
                endian = '<' if ei_data == 1 else '>'
                
                # Determine class (32 vs 64 bit)
                is_64bit = ei_class == self.ELF64_CLASS
                
                # Read program headers to find dynamic section
                e_phoff = struct.unpack(endian + 'I' if not is_64bit else endian + 'Q', 
                                      magic[52:60])[0]
                
                # For now, use file command output which is more reliable
                try:
                    result = subprocess.run(
                        ['file', '-iLz', str(path)],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0 and 'ELF' in result.stdout:
                        # Extract library list from file output
                        for line in result.stdout.split('\n'):
                            if 'shared object' in line or 'dynamic' in line.lower():
                                lib_name = line.split('/')[-1].strip()
                                libraries.append(lib_name)
                    
                    # Try to get symbols using readelf/nm
                    try:
                        sym_result = subprocess.run(
                            ['readelf', '-n', str(path)],
                            capture_output=True, text=True, timeout=5
                        )
                        
                        if 'Dynamic section' in sym_result.stdout:
                            for line in sym_result.stdout.split('\n'):
                                # Look for SONAME or other symbol info
                                parts = line.strip().split()
                                if len(parts) >= 2 and any(p.isdigit() for p in parts[:3]):
                                    symbols[parts[-1]] = {
                                        'type': 'dynamic',
                                        'value': parts[-1]
                                    }
                    except:
                        pass
                        
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    # Fallback: try to extract from raw ELF if possible
                    pass
        
        except Exception:
            pass
        
        return libraries, symbols
    
    def scan_directory(self, root_path: Path) -> AnalysisResult:
        """Scan a directory for all binaries."""
        result = AnalysisResult()
        
        # Find potential binary files
        extensions = {'.elf', '.so', '.a', '.ko', '.o', 
                     '.exe', '.dll', '.dylib', '.bin'}
        
        candidates = []
        for ext in extensions:
            candidates.extend(root_path.rglob(f'*{ext}'))
        
        # Also check common binary directories and files
        common_names = {'init', 'system', 'kernel', 'boot', 'cmdline', 
                       'recovery', 'update', 'service'}
        
        for name in common_names:
            candidates.extend(root_path.rglob(f'*{name}*'))
        
        # Add all regular files as fallback (limit to avoid memory issues)
        if not candidates:
            candidates = list(root_path.iterdir())[:1000]
        
        # Identify each candidate
        for path in candidates:
            if path.is_file():
                info = self.identify_file(path)
                result.binaries.append(info)
        
        # Check kernel version for EOL flags
        result.eol_flags.extend(self._check_kernels(root_path))
        
        # TODO: Add CVE checking (requires NVD API or local database)
        
        return result
    
    def _check_kernels(self, root_path: Path) -> List[EOLFlag]:
        """Check for known EOL kernel versions."""
        eol_flags = []
        
        # Common kernel version patterns to search
        kernel_patterns = [
            b'Linux version',
            b'FreeBSD ',
            b'BSD/OS ',
            b'Mac OS X',
            b'iOS ',
            b'Android '
        ]
        
        for pattern in kernel_patterns:
            try:
                matches = root_path.rglob(pattern)
                
                for match in matches[:10]:  # Limit to avoid too many results
                    if match.is_file():
                        with open(match, 'rb') as f:
                            content = f.read(4096).decode('utf-8', errors='ignore').lower()
                            
                            # Extract version string
                            import re
                            version_match = re.search(r'(\d+\.\d+)', content)
                            
                            if version_match:
                                version = version_match.group(1)
                                
                                # Check against known EOL lists (simplified)
                                eol_versions = {
                                    '4.4': {'eol_date': datetime(2019, 1, 1), 'source': 'Linux LTS'},
                                    '3.18': {'eol_date': datetime(2018, 6, 1), 'source': 'Android LTS'},
                                }
                                
                                if version in eol_versions:
                                    info = eol_versions[version]
                                    eol_flags.append(EOLFlag(
                                        component="Linux Kernel",
                                        version=version,
                                        eol_date=info['eol_date'],
                                        source=info['source']
                                    ))
                                
            except Exception:
                continue
        
        return eol_flags
    
    def get_summary(self, result: AnalysisResult) -> Dict[str, Any]:
        """Generate a summary of the analysis."""
        arch_counts = {}
        type_counts = {}
        
        for binary in result.binaries:
            arch_key = f"{binary.arch.name}_{binary.arch.bits}"
            type_counts[binary.type_name] = type_counts.get(binary.type_name, 0) + 1
            
            if arch_key not in arch_counts:
                arch_counts[arch_key] = 0
            arch_counts[arch_key] += 1
        
        summary = {
            'total_binaries': len(result.binaries),
            'by_type': type_counts,
            'by_architecture': arch_counts,
            'cve_count': len(result.cve_flags),
            'eol_count': len(result.eol_flags),
            'scan_time': datetime.now().isoformat(),
        }
        
        return summary


def main():
    """Demo/entry point for binary identification."""
    import sys
    
    # Default to current directory if no arguments provided
    root_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path.cwd()
    
    print(f"Scanning: {root_path}")
    print("=" * 60)
    
    identifier = BinaryIdentifier()
    result = identifier.scan_directory(root_path)
    
    # Print summary
    summary = identifier.get_summary(result)
    print("\nSUMMARY:")
    print(f"  Total binaries found: {summary['total_binaries']}")
    print(f"  By type: {summary['by_type']}")
    print(f"  By architecture: {summary['by_architecture']}")
    print(f"  CVE flags: {summary['cve_count']}")
    print(f"  EOL flags: {summary['eol_count']}")
    
    # Print detailed binary info
    if result.binaries:
        print("\nBINARY DETAILS:")
        for i, binary in enumerate(result.binaries[:20]):  # Limit output
            libs = ', '.join(binary.libraries[:5]) if binary.libraries else 'None'
            print(f"  {i+1}. {binary.name}")
            print(f"     Arch: {binary.arch}")
            print(f"     Libraries: {libs}")
    
    # Print flags
    if result.cve_flags:
        print("\nCVE FLAGS:")
        for flag in result.cve_flags[:20]:
            print(f"  - {flag}")
    
    if result.eol_flags:
        print("\nEOL FLAGS:")
        for flag in result.eol_flags:
            print(f"  - {flag}")


if __name__ == "__main__":
    main()