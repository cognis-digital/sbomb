package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
)

// CVE database - minimal embedded set for demonstration
var cveDB = map[string][]CVEEntry{
	"openssl": {
		{ID: "CVE-2019-3846", Versions: []string{"<1.1.1k"}, Severity: "High", Description: "TLS renegotiation DoS"},
		{ID: "CVE-2021-3711", Versions: []string{"<1.1.1l"}, Severity: "Medium", Description: "Heartbeat extension DoS"},
	},
	"libcurl": {
		{ID: "CVE-2020-8285", Versions: []string{"<7.69.1"}, Severity: "High", Description: "Heap-based buffer overflow"},
	},
	"glibc": {
		{ID: "CVE-2021-43443", Versions: []string{"<2.35"}, Severity: "Medium", Description: "Buffer overflow in getaddrinfo"},
	},
}

// EOL kernel database (simplified)
var eolKernels = map[string]EOLInfo{
	"4.19":  {EOLDate: time.Date(2025, 6, 1), Codename: "LTS"},
	"4.14":  {EOLDate: time.Date(2023, 12, 31), Codename: "LTS"},
	"4.9":   {EOLDate: time.Date(2022, 6, 15), Codename: "LTS"},
	"3.10":  {EOLDate: time.Date(2020, 12, 31), Codename: "LTS"},
}

type CVEEntry struct {
	ID          string   `json:"id"`
	Versions    []string `json:"versions,omitempty"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
}

type EOLInfo struct {
	EOLDate  time.Time `json:"eol_date"`
	Codename string    `json:"codename"`
}

// Binary metadata extracted from file analysis
type BinaryMeta struct {
	Path         string      `json:"path"`
	Name         string      `json:"name"`
	Type         string      `json:"type"`
	Architecture string      `json:"architecture,omitempty"`
	Version      string      `json:"version,omitempty"`
	Size         int64        `json:"size"`
	MIMEType     string      `json:"mime_type"`
}

// CycloneDX component with embedded metadata
type SBOMComponent struct {
	Name       string    `json:"name"`
	Type       string    `json:"type"`
	Version    string    `json:"version,omitempty"`
	Subtypes   []string  `json:"subtypes,omitempty"`
	MIMEType   string    `json:"mime_type,omitempty"`
	BinaryMeta BinaryMeta `json:"binary_metadata,omitempty"`
	CVEs       []CVE     `json:"cves,omitempty"`
	EOL        bool      `json:"eol,omitempty"`
}

// CVE embedded in component
type CVE struct {
	ID          string   `json:"id"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Versions    []string `json:"versions,omitempty"`
}

func identifyBinary(path string) (BinaryMeta, error) {
	info, err := os.Stat(path)
	if err != nil {
		return BinaryMeta{Path: path, Name: filepath.Base(path), Type: "unknown", Size: 0}, err
	}

	meta := BinaryMeta{
		Path:    path,
		Name:    filepath.Base(path),
		Type:    "unknown",
		Size:    info.Size(),
		MIMEType: mimeFromExtension(filepath.Ext(path)),
	}

	if info.IsDir() {
		return meta, nil
	}

	// Try to detect ELF headers for binaries
	if strings.Contains(meta.MIMEType, "x-data") || isELFFile(path) {
		meta.Type = "executable"
		
		// Extract architecture from ELF header if possible
		if arch := elfArchitecture(path); arch != "" {
			meta.Architecture = arch
		}

		// Try to extract version from binary name or common patterns
		if meta.Version, err = extractBinaryVersion(path); err == nil && meta.Version == "" {
			meta.Version = "detected"
		}
	} else if strings.Contains(meta.MIMEType, "x-shared") || isSharedLibrary(path) {
		meta.Type = "shared_library"
	}

	return meta, nil
}

func mimeFromExtension(ext string) string {
	mimes := map[string]string{
		".elf":  "application/x-data",
		".so.":  "application/x-sharedlib",
		".a":    "application/x-archive",
		".o":    "application/octet-stream",
		".bin":  "application/octet-stream",
	}

	for k, v := range mimes {
		if strings.HasSuffix(ext, k) || ext == k {
			return v
		}
	}
	return "application/octet-stream"
}

func isELFFile(path string) bool {
	data, err := os.ReadFile(path, 64)
	if err != nil {
		return false
	}
	
	// ELF magic number: 0x7f 'E' 'L' 'F'
	magic := []byte{0x7f, 0x45, 0x4c, 0x46}
	if bytes.Equal(data[:4], magic) {
		return true
	}

	// Also check for PE/COFF (Windows executables)
	if len(data) >= 2 && data[0] == 0x4d && data[1] == 0x5a { // 'M' 'Z'
		return true
	}

	return false
}

func elfArchitecture(path string) string {
	data, err := os.ReadFile(path, 64)
	if err != nil {
		return ""
	}

	// ELF class: 1 = 32-bit, 2 = 64-bit (byte 5)
	if len(data) < 6 {
		return "unknown"
	}

	class := data[5]
	var arch string
	switch class {
	case 1:
		arch = "x86_32"
	case 2:
		arch = "x86_64"
	default:
		arch = fmt.Sprintf("elf%d", class)
	}

	return arch
}

func isSharedLibrary(path string) bool {
	if filepath.Ext(path) == ".so" || strings.Contains(filepath.Base(path), ".so.") {
		data, err := os.ReadFile(path, 64)
		if err != nil {
			return false
		}
		return bytes.Equal(data[:4], []byte{0x7f, 0x45, 0x4c, 0x46})
	}
	return false
}

func extractBinaryVersion(path string) (string, error) {
	data, err := os.ReadFile(path, 1024)
	if err != nil {
		return "", err
	}

	// Look for common version patterns in binary headers
	versionPatterns := []regexp.Regexp{
		regexp.MustCompile(`(?i)(version|ver)\s*[:=]\s*(\d+(\.\d+)*)`),
		regexp.MustCompile(`(?i)BUILD_(VERSION)?=(\d+(\.\d+)*)`),
	}

	for _, pattern := range versionPatterns {
		matches := pattern.FindSubmatch(data)
		if matches != nil && len(matches) >= 3 {
			versionStr := string(matches[2])
			versionStr = strings.TrimSpace(versionStr)
			if versionStr != "" {
				return versionStr, nil
			}
		}
	}

	return "", nil
}

func scanDirectory(rootPath string) ([]BinaryMeta, error) {
	var binaries []BinaryMeta

	err := filepath.WalkDir(rootPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() && (d.Type().IsRegular() || d.Type().IsSymlink()) {
			meta, _ := identifyBinary(path)
			if meta.Size > 0 { // Skip empty files
				binaries = append(binaries, meta)
			}
		}

		return nil
	})

	if err != nil {
		return binaries, err
	}

	return binaries, nil
}

func matchCVEs(components []SBOMComponent) ([]SBOMComponent, error) {
	var updatedComponents []SBOMComponent

	for _, comp := range components {
		cveMatches := []CVE{}

		// Check component name against CVE database
		nameLower := strings.ToLower(comp.Name)
		
		for libraryName, cves := range cveDB {
			if strings.Contains(nameLower, libraryName) || 
			   strings.Contains(libraryName, strings.Split(nameLower, ".")[0]) {
				for _, entry := range cves {
					cveMatches = append(cveMatches, CVE{
						ID:          entry.ID,
						Severity:    entry.Severity,
						Description: entry.Description,
						Versions:    entry.Versions,
					})
				}
			}
		}

		if len(cveMatches) > 0 {
			comp.CVEs = cveMatches
		}

		updatedComponents = append(updatedComponents, comp)
	}

	return updatedComponents, nil
}

func checkKernelEOL(components []SBOMComponent) ([]SBOMComponent, error) {
	var updatedComponents []SBOMComponent

	for _, comp := range components {
		if strings.Contains(strings.ToLower(comp.Name), "linux") || 
		   strings.Contains(strings.ToLower(comp.Name), "kernel") {
			
			// Extract kernel version from name (e.g., "linux-4.19.0" -> "4.19")
			versionMatch := regexp.MustCompile(`(?i)(linux|kernel)[-_](\d+\.\d+).*`)
			matches := versionMatch.FindStringSubmatch(comp.Name)
			
			if len(matches) >= 3 {
				majorMinor := matches[2]
				
				if eol, exists := eolKernels[majorMinor]; exists {
					comp.EOL = time.Now().After(eol.EOLDate)
					
					if comp.EOL {
						// Add EOL warning metadata
						comp.BinaryMeta.Type = "eol_kernel"
						comp.BinaryMeta.Version = majorMinor + "-EOL"
					}
				}
			}
		}

		updatedComponents = append(updatedComponents, comp)
	}

	return updatedComponents, nil
}

func generateSBOM(binaries []BinaryMeta) (*cyclonedx.BOM, error) {
	bom := &cyclonedx.BOM{
		Meta: cyclonedx.Metadata{
			Timestamp: time.Now(),
			Tools: cyclonedx.Tools{
				Name:    "sbomb",
				Version: "1.0.0",
			},
		},
	}

	// Convert binaries to CycloneDX components
	var components []SBOMComponent

	for _, bin := range binaries {
		component := SBOMComponent{
			Name:       filepath.Base(bin.Path),
			Type:       "application" + strings.TrimPrefix(string(bin.MIMEType), "application/"),
			Version:    bin.Version,
			MIMEType:   string(bin.MIMEType),
			BinaryMeta: bin,
		}

		// Determine subtype based on type
		switch bin.Type {
		case "executable":
			component.Subtypes = []string{"elf"}
		case "shared_library":
			component.Subtypes = []string{"so"}
		}

		components = append(components, component)
	}

	// Apply CVE matching
	componentsWithCVEs, err := matchCVEs(components)
	if err != nil {
		return bom, err
	}
	components = componentsWithCVEs

	// Apply EOL checking
	componentsWithEOL, err := checkKernelEOL(components)
	if err != nil {
		return bom, err
	}
	components = componentsWithEOL

	bom.Components = cyclonedx.ComponentList(components)

	return bom, nil
}

func formatSBOM(bom *cyclonedx.BOM) (string, error) {
	jsonBytes, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return "", err
	}

	// Add XML header for CycloneDX compatibility
	xmlHeader := `<?xml version="1.0" encoding="UTF-8"?>` + string(jsonBytes)
	
	return xmlHeader, nil
}

func printSummary(bom *cyclonedx.BOM) {
	fmt.Printf("\n=== SBOMB Summary ===\n")
	fmt.Printf("Total Components: %d\n", len(bom.Components))
	
	cveCount := 0
	eolCount := 0
	
	for _, comp := range bom.Components {
		if len(comp.CVEs) > 0 {
			cveCount += len(comp.CVEs)
		}
		if comp.EOL {
			eolCount++
		}
	}

	fmt.Printf("Components with CVEs: %d\n", cveCount)
	fmt.Printf("EOL Kernels: %d\n", eolCount)

	if cveCount > 0 || eolCount > 0 {
		fmt.Println("\n=== Issues Found ===")
		
		for _, comp := range bom.Components {
			if len(comp.CVEs) > 0 {
				fmt.Printf("\n%s (CVEs):\n", comp.Name)
				for _, cve := range comp.CVEs {
					fmt.Printf("  - %s [%s]: %s\n", cve.ID, cve.Severity, cve.Description)
				}
			}
			
			if comp.EOL {
				fmt.Printf("\n%s (EOL):\n", comp.Name)
				fmt.Printf("  Version: %s\n", comp.Version)
			}
		}
	}

	fmt.Println("\n=== Done ===")
}

func main() {
	// Demo: Create a temporary test filesystem
	testDir := "/tmp/sbomb-test"
	
	// Clean up if exists
	os.RemoveAll(testDir)
	
	// Create test structure
	os.MkdirAll(filepath.Join(testDir, "bin"), 0755)
	os.MkdirAll(filepath.Join(testDir, "usr", "lib"), 0755)

	// Create dummy ELF files for testing
	testBinaries := []struct{
		path string
		name string
		size int64
	}{
		{filepath.Join(testDir, "bin/sh"), "/bin/sh", 1024},
		{filepath.Join(testDir, "usr/lib/openssl.so.1.1"), "/usr/lib/openssl.so.1.1", 512},
		{filepath.Join(testDir, "usr/lib/curl.so.7.68.0"), "/usr/lib/curl.so.7.68.0", 256},
		{filepath.Join(testDir, "bin/kernel-4.19.0"), "/bin/kernel-4.19.0", 2048},
	}

	for _, b := range testBinaries {
		os.MkdirAll(filepath.Dir(b.path), 0755)
		
		// Create ELF magic header
		data := []byte{0x7f, 0x45, 0x4c, 0x46} // ELF magic
		if b.name == "kernel-4.19.0" {
			data = append(data, 2) // 64-bit
		} else {
			data = append(data, 1) // 32-bit
		}
		
		padding := make([]byte, b.size-len(data))
		os.WriteFile(b.path, append(data, padding...), 0755)
	}

	fmt.Println("=== SBOMB Demo ===")
	fmt