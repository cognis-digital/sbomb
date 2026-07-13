"""
polyglot/python/filesystem_traversal.py

CycloneDX SBOM Generator from Firmware Filesystem

Traverses an unpacked firmware root filesystem, identifies components using
heuristics (file names, paths, magic bytes), checks for known CVEs and EOL kernels,
and outputs a valid CycloneDX BOM.
"""

import os
import re
import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple
from pathlib import Path
from datetime import datetime, timezone
import hashlib


# =============================================================================
# Data Classes for Component Identification
# =============================================================================

@dataclass
class FileMetadata:
    """Raw metadata extracted from a file."""
    path: str
    size: int
    mtime: float
    mode: str = ""
    magic_bytes: bytes = b""
    name_parts: List[str] = field(default_factory=list)

@dataclass
class IdentifiedComponent:
    """A component identified from filesystem analysis."""
    name: str
    version: str
    type: str  # "library", "binary", "config", etc.
    purl: Optional[str] = None
    cpe: Optional[str] = None
    files: List[FileMetadata] = field(default_factory=list)
    hashes: Dict[str, str] = field(default_factory=dict)

# =============================================================================
# Filesystem Traversal Engine
# =============================================================================

class FirmwareTraverser:
    """
    Traverse firmware filesystem and extract file metadata.
    
    Uses a two-pass approach:
    1. Quick scan for size/mtime/permissions
    2. Deep scan with magic byte detection (configurable depth)
    """
    
    # Common binary extensions that indicate executables/libraries
    BINARY_EXTENSIONS = {
        '.bin', '.elf', '.so', '.a', '.o', '.pyc', 
        '.exe', '.dll', '.dylib', '.jar', '.war'
    }
    
    # Config files often contain version strings
    CONFIG_PATTERNS = [
        r'version\s*[:=]\s*(\S+)',
        r'#\s*VERSION:\s*(\S+)',
        r'__version__\s*=\s*"([^"]+)"',
    ]
    
    # Known magic bytes for quick identification
    MAGIC_DB = {
        b'\x7fELF': 'elf_binary',
        b'\x00\x03\x01\x0e': 'pe_executable',  # PE32
        b'MZ': 'pe_executable',  # PE16
        b'PK\x03\x04': 'zip_archive',
        b'GIF87a': 'gif_image',
        b'GIF89a': 'gif_image',
        b'\x89PNG\r\n\x1a\n': 'png_image',
    }
    
    def __init__(self, root_path: str, max_depth: int = 50, 
                 min_size: int = 64):
        self.root_path = os.path.abspath(root_path)
        self.max_depth = max_depth
        self.min_size = min_size
        self.components: List[IdentifiedComponent] = []
        
    def traverse(self) -> List[FileMetadata]:
        """
        Perform initial traversal and collect file metadata.
        
        Returns list of FileMetadata objects with basic info.
        """
        files = []
        
        for dirpath, _, filenames in os.walk(
            self.root_path, 
            maxdepth=self.max_depth
        ):
            # Skip common hidden directories
            basename = os.path.basename(dirpath)
            if basename.startswith('.') and basename not in {'.git', '.svn'}:
                continue
                
            for filename in filenames:
                filepath = os.path.join(dirpath, filename)
                
                try:
                    stat_info = os.stat(filepath)
                    
                    # Skip very small files (likely metadata/fragments)
                    if stat_info.st_size < self.min_size:
                        continue
                    
                    # Skip symlinks and special files
                    if not os.path.isfile(filepath):
                        continue
                        
                    metadata = FileMetadata(
                        path=filepath,
                        size=stat_info.st_size,
                        mtime=stat_info.st_mtime,
                        mode=os.stat(filepath).st_mode & 0o777
                    )
                    
                    # Extract name parts for heuristic matching
                    metadata.name_parts = self._extract_name_parts(filename)
                    
                    files.append(metadata)
                    
                except (OSError, IOError):
                    # Skip files that can't be accessed
                    continue
        
        return files
    
    def _extract_name_parts(self, filename: str) -> List[str]:
        """Extract meaningful parts from filename for matching."""
        name = os.path.basename(filename).lower()
        
        # Remove common extensions
        base = name
        for ext in self.BINARY_EXTENSIONS:
            if name.endswith(ext):
                base = name[:-len(ext)]
                break
        
        return [p.strip().lower() for p in re.split(r'[-_.]', base) if p]

# =============================================================================
# Component Identification Engine
# =============================================================================

class ComponentIdentifier:
    """
    Identify components from file metadata using multiple heuristics.
    
    Heuristics include:
    - Filename pattern matching against known libraries
    - Magic byte detection
    - Path-based inference (e.g., /lib/libssl.so -> openssl)
    - Version string extraction
    """
    
    # Known library name patterns and their canonical names
    LIBRARY_PATTERNS = {
        r'.*openssl.*': 'openssl',
        r'.*zlib.*': 'zlib',
        r'.*libpng.*': 'libpng',
        r'.*libjpeg.*': 'libjpeg',
        r'.*sqlite3.*': 'sqlite3',
        r'.*libxml2.*': 'libxml2',
        r'.*libcurl.*': 'libcurl',
        r'.*libffi.*': 'libffi',
        r'.*bzip2.*': 'bzip2',
        r'.*lzma.*': 'xz_utils',
        r'.*glibc.*': 'glibc',
        r'.*musl.*': 'musl_libc',
    }
    
    # Path-based inference rules
    PATH_RULES = {
        '/lib/lib': 'library',
        '/usr/lib/lib': 'library',
        '/bin/': 'binary',
        '/sbin/': 'binary',
        '/etc/': 'config',
        '/var/log/': 'log',
    }
    
    def __init__(self, file_metadata: List[FileMetadata]):
        self.files = file_metadata
    
    def identify(self) -> List[IdentifiedComponent]:
        """
        Identify components from all discovered files.
        
        Returns list of IdentifiedComponent objects with inferred metadata.
        """
        identified = []
        seen_hashes = {}  # Avoid duplicate detection
        
        for meta in self.files:
            component = self._identify_single_file(meta)
            
            if component and not self._is_duplicate(component, seen_hashes):
                identified.append(component)
                
        return identified
    
    def _identify_single_file(self, meta: FileMetadata) -> Optional[IdentifiedComponent]:
        """Identify a single file as a potential component."""
        
        # 1. Try magic byte detection first
        if meta.magic_bytes:
            for magic, component_type in self.MAGIC_DB.items():
                if meta.magic_bytes.startswith(magic):
                    return self._create_component_from_magic(
                        meta, component_type
                    )
        
        # 2. Try filename pattern matching
        matched = False
        for pattern, canonical_name in self.LIBRARY_PATTERNS.items():
            if re.search(pattern, meta.path, re.IGNORECASE):
                return self._create_component_from_pattern(
                    meta, canonical_name
                )
        
        # 3. Try path-based inference
        component_type = 'binary'  # default
        
        for prefix, comp_type in self.PATH_RULES.items():
            if meta.path.startswith(prefix):
                component_type = comp_type
                break
        
        # 4. Extract version from filename or content (if small enough)
        version = self._extract_version_from_filename(meta)
        
        name = self._infer_name(meta, version)
        
        return IdentifiedComponent(
            name=name if name else meta.path.split('/')[-1],
            version=version or 'unknown',
            type='library' if component_type == 'library' else 
                ('binary' if component_type == 'binary' else 'config'),
            files=[meta]
        )
    
    def _create_component_from_magic(self, meta: FileMetadata, 
                                    comp_type: str) -> IdentifiedComponent:
        """Create component from magic byte detection."""
        name = self._infer_name(meta, None)
        
        return IdentifiedComponent(
            name=name if name else f"magic_{comp_type}",
            version="unknown",
            type=comp_type,
            files=[meta]
        )
    
    def _create_component_from_pattern(self, meta: FileMetadata, 
                                      canonical_name: str) -> IdentifiedComponent:
        """Create component from filename pattern matching."""
        
        # Extract version from filename if present
        version = self._extract_version_from_filename(meta)
        
        return IdentifiedComponent(
            name=canonical_name,
            version=version or "unknown",
            type='library',
            files=[meta]
        )
    
    def _infer_name(self, meta: FileMetadata, 
                   version: Optional[str]) -> str:
        """Infer a reasonable component name."""
        
        # Try to extract from filename
        base = os.path.basename(meta.path)
        
        # Remove common extensions
        for ext in self.BINARY_EXTENSIONS:
            if base.endswith(ext):
                base = base[:-len(ext)]
                break
        
        # Clean up path
        name_parts = [p.strip() for p in re.split(r'[-_.]', base.lower()) 
                     if len(p) > 1]
        
        return '_'.join(name_parts[:3])  # Limit to first 3 parts
    
    def _extract_version_from_filename(self, meta: FileMetadata) -> Optional[str]:
        """Extract version from filename patterns."""
        
        name = os.path.basename(meta.path).lower()
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+(\.\d+)?)',  # Simple semver
            r'version-?(\S+)',
            r'_v?(\d+\.\d+(\.\d+)?)_',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, name)
            if match:
                version_str = match.group(1)
                # Clean up common prefixes/suffixes
                clean_version = re.sub(r'^[vV_]+|_[0-9]+$', '', version_str)
                return clean_version
        
        return None
    
    def _is_duplicate(self, component: IdentifiedComponent, 
                     seen_hashes: Dict[str, str]) -> bool:
        """Check if this is a duplicate of an already identified component."""
        
        # Create hash key from name and version
        key = f"{component.name}:{component.version}"
        
        if key in seen_hashes:
            return True
        
        seen_hashes[key] = len(seen_hashes) + 1
        return False

# =============================================================================
# CVE and EOL Checking Engine
# =============================================================================

class VulnerabilityChecker:
    """
    Check identified components against known vulnerabilities.
    
    Uses lightweight data structures for quick lookups. In production,
    this would integrate with a proper vulnerability database API.
    """
    
    # Sample CVE database (in real usage, load from JSON/DB)
    SAMPLE_CVES = {
        'openssl': [
            {'version': '<1.0.2', 'cve': 'CVE-2019-3846', 'severity': 'high'},
            {'version': '>=1.1.0,<1.1.1', 'cve': 'CVE-2019-1571', 'severity': 'medium'},
        ],
        'glibc': [
            {'version': '<2.26', 'cve': 'CVE-2018-14613', 'severity': 'high'},
        ],
    }
    
    # Sample EOL kernels (year of end-of-life)
    EOL_KERNELS = {
        '2.6.32': 2015,
        '3.2.0': 2014,
        '3.4.0': 2014,
        '3.8.0': 2014,
    }
    
    def __init__(self):
        self.vulnerabilities: List[Dict[str, Any]] = []
        
    def check_all(self, components: List[IdentifiedComponent]) -> None:
        """Check all components for vulnerabilities."""
        
        for component in components:
            if not component.version or component.version == 'unknown':
                continue
                
            self._check_cves(component)
            self._check_eol_kernel(component)
    
    def _check_cves(self, component: IdentifiedComponent) -> None:
        """Check a single component against CVE database."""
        
        name = component.name.lower()
        version_str = component.version
        
        # Parse version for comparison
        parsed_version = self._parse_version(version_str)
        
        if not parsed_version:
            return
        
        # Check against known CVEs
        for lib_name, cve_list in self.SAMPLE_CVES.items():
            if name.startswith(lib_name.lower()):
                for entry in cve_list:
                    if self._version_matches(entry['version'], parsed_version):
                        self.vulnerabilities.append({
                            'component': component.name,
                            'cve': entry['cve'],
                            'severity': entry['severity'],
                            'affected_version': version_str,
                            'threshold': entry['version'],
                        })
    
    def _check_eol_kernel(self, component: IdentifiedComponent) -> None:
        """Check if component might be running an EOL kernel."""
        
        # Look for kernel-like components
        name_lower = component.name.lower()
        
        if any(kw in name_lower for kw in ['linux', 'kernel', 'u-boot']):
            version_str = component.version
            
            parsed_version = self._parse_version(version_str)
            
            if parsed_version:
                # Check against EOL kernel list
                for eol_ver, eol_year in self.EOL_KERNELS.items():
                    if self._version_matches(eol_ver, parsed_version):
                        self.vulnerabilities.append({
                            'component': component.name,
                            'type': 'eol_kernel',
                            'kernel_version': version_str,
                            'end_of_life_year': eol_year,
                        })
    
    def _parse_version(self, version: str) -> Optional[str]:
        """Parse and normalize version string for comparison."""
        
        if not version or version == 'unknown':
            return None
        
        # Remove common prefixes/suffixes
        clean = re.sub(r'^[vV_]+|_[0-9]+$', '', version)
        
        # Extract numeric parts only
        nums = re.findall(r'(\d+(?:\.\d+)*)', clean)
        
        if nums:
            return '.'.join(nums[:3])  # Limit to major.minor.patch
        
        return None
    
    def _version_matches(self, threshold: str, parsed: str) -> bool:
        """Check if parsed version matches a threshold condition."""
        
        if not parsed or not threshold:
            return False
        
        # Parse threshold (e.g., "<1.0.2" means less than 1.0.2)
        op, thresh_ver = self._parse_threshold(threshold)
        
        if not op:
            return True  # Unknown operator, assume match
        
        try:
            current_parts = [int(x) for x in parsed.split('.')]
            threshold_parts = [int(x) for x in thresh_ver.split('.')]
            
            if len(current_parts) < len(threshold_parts):
                current_parts.extend([0] * (len(threshold_parts) - len(current_parts)))
            
            # Compare based on operator
            if op == '<':
                return current_parts < threshold_parts
            elif op == '>=':
                return current_parts >= threshold_parts
            else:
                return True  # Unknown, assume match
                
        except (ValueError, IndexError):
            return True
    
    def _parse_threshold(self, threshold: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse threshold string like "<1.0.2" into operator and version."""
        
        if not threshold:
            return None, None
        
        # Extract operator and version
        match = re.match(r'^([<>=]+)(\d+\.\d+(\.\d+)?)$', threshold)
        
        if match:
            op = match.group(1)
            ver = match.group(2)
            return op, ver
        
        return None, threshold

# =============================================================================
# CycloneDX BOM Generator
# =============================================================================

class CycloneDXGenerator:
    """
    Generate a valid CycloneDX Software Bill of Materials (SBOM).
    
    Implements the 1.4 specification with support for:
    - Component identification via purl and CPE
    - Vulnerability annotations
    - EOL kernel warnings
    """
    
    # CycloneDX 1.4 namespace constants
    NS = "https://cyclonedx.org/schema/bom-1.4