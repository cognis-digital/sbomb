package main

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
)

// Config holds tool configuration
type Config struct {
	Path         string
	Concurrency  int
	CVEFile      string
	EOLKernels   []string
	MinVersion   string
}

// DefaultConfig returns sensible defaults
func DefaultConfig() *Config {
	return &Config{
		Path:        ".",
		Concurrency: 4,
		CVEFile:     "cve-db.json",
		EOLKernels:  []string{"5.15", "6.1", "6.2"},
	}
}

// CVEEntry represents a known vulnerability
type CVEEntry struct {
	ID        string   `json:"id"`
	Package   string   `json:"package"`
	Version   string   `json:"version"`
	CPE       string   `json:"cpe,omitempty"`
	Summary   string   `json:"summary"`
	Severity  string   `json:"severity"`
	Affected  []string `json:"affected_versions"`
}

// EOLKernelEntry represents an end-of-life kernel
type EOLKernelEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	EOLDate string `json:"eol_date"`
	Notes   string `json:"notes,omitempty"`
}

// PackageInfo holds parsed package metadata
type PackageInfo struct {
	Name       string
	Version    string
	Arch       string
	Type       string // deb, rpm, apk, generic
	Source     string
	License    []string
	Description string
	Dependencies []PackageDependency
	CVEs        []CVEEntry
	EOL         bool
}

// PackageDependency represents a package dependency
type PackageDependency struct {
	Name    string
	Version string
	Type    string // runtime, build, optional
}

// CycloneDXOutput holds the SBOM structure
type CycloneDXOutput struct {
	cyclonedx.BOM
	Components []cyclonedx.Component `json:"components"`
	CVEs        []CVEEntry            `json:"cves,omitempty"`
	EOLKernels  []EOLKernelEntry      `json:"eol_kernels,omitempty"`
	Metadata    cyclonedx.Metadata   `json:"metadata"`
}

// Global variables for shared state
var (
	globalConfig     *Config
	cveDatabase      = make(map[string][]CVEEntry)
	eolKernels       = make(map[string]EOLKernelEntry)
	packages         = make(map[string]*PackageInfo)
	mu               sync.Mutex
	startTime        time.Time
	fileCount        int64
	processedBytes   int64
)

// Init initializes global state and loads databases
func Init(cfg *Config) error {
	globalConfig = cfg
	if err := loadCVEDatabase(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: loading CVE database: %v\n", err)
	}
	if err := loadEOLKernels(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: loading EOL kernels: %v\n", err)
	}
	startTime = time.Now()
	return nil
}

// loadCVEDatabase loads CVE data from file or uses defaults
func loadCVEDatabase() error {
	if globalConfig.CVEFile == "" || !fileExists(globalConfig.CVEFile) {
		cveDatabase["default"] = defaultCVEs
		return nil
	}
	
	data, err := os.ReadFile(globalConfig.CVEFile)
	if err != nil {
		return fmt.Errorf("reading CVE file: %w", err)
	}
	
	var entries []CVEEntry
	if err := json.Unmarshal(data, &entries); err == nil && len(entries) > 0 {
		cveDatabase["custom"] = entries
	} else if err != nil {
		cveDatabase["default"] = defaultCVEs
	}
	return nil
}

// loadEOLKernels loads EOL kernel data
func loadEOLKernels() error {
	for _, ver := range globalConfig.EOLKernels {
		eolKernels[ver] = EOLKernelEntry{
			Name:    "linux-kernel",
			Version: ver,
			EOLDate: getEOldate(ver),
			Notes:   fmt.Sprintf("Kernel %s reached end-of-life on %s", ver, getEOldate(ver)),
		}
	}
	return nil
}

// fileExists checks if a file exists
func fileExists(name string) bool {
	info, err := os.Stat(name)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// getEOldate returns an EOL date for a kernel version
func getEOldate(version string) string {
	switch version {
	case "5.15":
		return "2026-03"
	case "6.1":
		return "2027-09"
	case "6.2":
		return "2028-03"
	default:
		return "TBD"
	}
}

// defaultCVEs provides some sample CVE entries
var defaultCVEs = []CVEEntry{
	{
		ID:        "CVE-2024-1234",
		Package:   "linux-kernel",
		Version:   "5.15.0",
		CPE:       "cpe:2.3:o:kernel:linux:5.15:*:*:*:*:*:*:*",
		Summary:   "Memory corruption in network stack",
		Severity:  "High",
		Affected:  []string{"<6.1.0"},
	},
	{
		ID:        "CVE-2024-5678",
		Package:   "openssl",
		Version:   "3.0.0",
		CPE:       "cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*",
		Summary:   "TLS handshake verification bypass",
		Severity:  "Critical",
		Affected:  []string{"<3.0.1"},
	},
}

// traverseFilesystem walks the directory tree and extracts packages
func traverseFilesystem(root string) error {
	root = filepath.Clean(root)
	if root == "." || root == "" {
		root, _ = os.Getwd()
	}
	
	var wg sync.WaitGroup
	sem := make(chan struct{}, globalConfig.Concurrency)
	
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		
		select {
		case sem <- struct{}{}:
		default:
			wg.Wait()
			<-sem
		}
		
		defer func() { <-sem }()
		
		name := d.Name()
		if d.IsDir() {
			return nil
		}
		
		fileCount++
		info, err := d.Info()
		if err != nil {
			return err
		}
		processedBytes += info.Size()
		
		// Skip non-package files
		if !isPackageFile(path) {
			return nil
		}
		
		wg.Add(1)
		go func(p string, d fs.DirEntry) {
			defer wg.Done()
			
			pkgInfo, err := extractPackage(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: extracting %s: %v\n", p, err)
				return
			}
			
			mu.Lock()
			key := pkgKey(pkgInfo.Name, pkgInfo.Version)
			if existing, ok := packages[key]; ok {
				existing.Merge(pkgInfo)
			} else {
				packages[key] = pkgInfo
			}
			mu.Unlock()
			
			// Check for CVEs and EOL status
			checkCVEs(pkgInfo.Name, pkgInfo.Version, pkgInfo.CVEs)
			if isEOLKernel(pkgInfo.Name, pkgInfo.Version) {
				pkgInfo.EOL = true
			}
		}(path, d)
		
		return nil
	})
	
	wg.Wait()
	close(sem)
	
	fileCount-- // Adjust for final close
	
	if err != nil {
		return fmt.Errorf("traversing filesystem: %w", err)
	}
	
	fmt.Printf("Processed %d files, %.2f MB\n", fileCount+int64(len(packages)), float64(processedBytes)/1024/1024)
	return nil
}

// isPackageFile checks if a file is likely a package archive
func isPackageFile(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	
	// Common package formats
	if ext == ".deb" || ext == ".rpm" || ext == ".apk" || 
	   ext == ".arj" || ext == ".tar.gz" || ext == ".tgz" ||
	   ext == ".xz" || ext == ".lzma" {
		return true
	}
	
	// Check for package manager indexes
	if strings.Contains(strings.ToLower(path), "apkindex.xml") ||
	   strings.Contains(strings.ToLower(path), "dpkg-status") ||
	   strings.Contains(strings.ToLower(path), "rpmdb") {
		return true
	}
	
	return false
}

// extractPackage extracts metadata from a package file
func extractPackage(path string) (*PackageInfo, error) {
	info := &PackageInfo{Type: "generic"}
	
	ext := strings.ToLower(filepath.Ext(path))
	
	switch ext {
	case ".deb":
		return extractDeb(path)
	case ".rpm":
		return extractRPM(path)
	case ".apk", ".arj":
		return extractAPK(path)
	default:
		if strings.Contains(strings.ToLower(path), "control") || 
		   strings.Contains(strings.ToLower(path), "dpkg-status") {
			return extractControlFile(path)
		}
		if strings.Contains(strings.ToLower(path), "apkindex.xml") {
			return extractAPKIndex(path)
		}
		return nil, fmt.Errorf("unknown package format: %s", ext)
	}
}

// extractDeb handles Debian packages
func extractDeb(path string) (*PackageInfo, error) {
	info := &PackageInfo{Type: "deb"}
	
	f, err := os.Open(path)
	if err != nil {
		return info, fmt.Errorf("opening deb file: %w", err)
	}
	defer f.Close()
	
	tarReader := tar.NewReader(f)
	
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return info, fmt.Errorf("reading deb archive: %w", err)
		}
		
		name := header.Name
		
		// Parse control.tar.gz contents
		if strings.Contains(name, "control.tar") || 
		   (header.Typeflag == '5' && name == "control.tar") {
			controlReader := tar.NewReader(tarReader)
			
			for {
				chdr, err := controlReader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					return info, fmt.Errorf("reading control: %w", err)
				}
				
				switch chdr.Name {
				case "control":
					content, err := io.ReadAll(controlReader)
					if err == nil {
						info = parseControlFile(string(content))
					}
				case "md5sums.txt":
					// Verify integrity if needed
				default:
					// Ignore other control files for now
				}
			}
		} else if header.Typeflag == '5' {
			// Rootfs tar archive - extract from filesystem
			info = extractFromRootfs(tar.NewReader(f))
		}
		
		if info != nil && (info.Name != "" || info.Version != "") {
			return info, nil
		}
	}
	
	return info, nil
}

// parseControlFile parses a Debian control file
func parseControlFile(content string) *PackageInfo {
	info := &PackageInfo{Type: "deb"}
	
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			value := strings.TrimSpace(line[idx+1:])
			
			switch key {
			case "package":
				info.Name = value
			case "version":
				info.Version = value
			case "architecture":
				info.Arch = value
			case "source":
				info.Source = value
			case "license":
				if info.License == nil {
					info.License = make([]string, 0)
				}
				info.License = append(info.License, value)
			case "description":
				info.Description = value
			case "depends":
				parseDependencies(value, &info.Dependencies)
			case "pre-depends", "recommends", "suggests", "enhances":
				// Could add more dependency types here
			}
		}
	}
	
	return info
}

// parseDependencies parses a comma-separated dependency list
func parseDependencies(depStr string, deps *[]PackageDependency) {
	if depStr == "" {
		return
	}
	
	for _, dep := range strings.Split(depStr, ",") {
		dep = strings.TrimSpace(dep)
		if dep == "" {
			continue
		}
		
		var name, version string
		if idx := strings.Index(dep, "="); idx > 0 {
			name = strings.TrimSpace(dep[:idx])
			version = strings.TrimSpace(dep[idx+1:])
		} else {
			name = dep
		}
		
		*deps = append(*deps, PackageDependency{
			Name:    name,
			Version: version,
			Type:    "runtime",
		})
	}
}

// extractRPM handles RPM packages
func extractRPM(path string) (*PackageInfo, error) {
	info := &PackageInfo{Type: "rpm"}
	
	f, err := os.Open(path)
	if err != nil {
		return info, fmt.Errorf("opening rpm file: %w", err)
	}
	defer f.Close()
	
	tarReader := tar.NewReader(f)
	
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return info, fmt.Errorf("reading rpm archive: %w", err)
		}
		
		name := header.Name
		
		if strings.Contains(name, "rpmdb") || 
		   (header.Typeflag == '5' && name == "rpmdb") {
			rpmReader := tar.NewReader(tarReader)
			
			for {
				chdr, err := rpmReader.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					return info, fmt.Errorf("reading rpmdb: %w", err)
				}
				
				switch chdr.Name {
				case "HEADER":
					content, err := io.ReadAll(rpmReader)
					if err == nil {
						info = parseRPMHeader(string(content))
					}
				default:
					// Ignore other rpmdb files
				}
				
				if info != nil && (info.Name != "" || info.Version != "") {
					return info, nil
				}
			}
		} else if header.Typeflag == '5' {
			info = extractFromRootfs(tar.NewReader(f))
		}
		
		if info != nil && (info.Name != "" || info.Version != "") {
			return info, nil
		}
	}
	
	return info, nil
}

// parseRPMHeader parses RPM header data
func parseRPMHeader(content string) *PackageInfo {
	info := &PackageInfo{Type: "rpm"}
	
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx := strings.Index(line, ":"); idx > 0 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			value := strings.TrimSpace(line[idx+1:])
			
			switch key {
			case "name":
				info.Name = value
			case "version":
				info.Version = value
			case "epoch":
				if info.Version == "" {
					info.Version =