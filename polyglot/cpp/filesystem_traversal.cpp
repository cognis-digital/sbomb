// polyglot/cpp/filesystem_traversal.cpp
// sbomb - CycloneDX SBOM Generator from Firmware Root Filesystem
// Compile with: g++ -std=c++17 -O2 -o sbomb filesystem_traversal.cpp
// Run with: ./sbomb /path/to/firmware/root

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <filesystem>
#include <regex>
#include <iomanip>
#include <ctime>
#include <chrono>

namespace fs = std::filesystem;

// ============================================================================
// Configuration & Constants
// ============================================================================

constexpr int MAX_DEPTH = 50;
constexpr size_t MAX_COMPONENTS = 10000;
constexpr size_t MAX_FILES_PER_DIR = 1000;
constexpr size_t BUFFER_SIZE = 64 * 1024;

// CycloneDX version
constexpr std::string_view CYCLONEDX_VERSION = "1.5";
constexpr std::string_view SBOMB_VERSION = "1.0.0";

// Known EOL kernel versions (year, month) - format: YYYY-MM
struct KernelEOL {
    int year;
    int month;
    std::string name;
};

const std::vector<KernelEOL> KERN_EOL_LIST = {
    {"2014", "03", "Ubuntu 14.04 LTS"},
    {"2015", "06", "CentOS 7 (some packages)"},
    {"2018", "09", "Debian 9 Stretch"},
    {"2019", "04", "Ubuntu 18.04 LTS"},
};

// ============================================================================
// Data Structures
// ============================================================================

struct Component {
    std::string name;
    std::string version;
    std::string type = "library"; // library, application, file, framework, etc.
    std::map<std::string, std::string> purl;
    std::vector<std::string> hashes;
    std::vector<std::string> licenses;
    std::vector<CVEEntry> cves;
    bool eol = false;
    std::string eol_reason;
};

struct CVEEntry {
    std::string id;
    int severity = 0; // 1-4, 5-8, 9-10
    std::string description;
    std::string published_date;
    bool fixed = false;
    std::string fix_version;
};

struct CycloneDXBOM {
    std::string metadata;
    std::vector<Component> components;
    int version = 1;
    
    void addComponent(const Component& c) {
        if (components.size() < MAX_COMPONENTS) {
            components.push_back(c);
        }
    }
};

struct ScanResult {
    CycloneDXBOM bom;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    int total_files = 0;
    int packages_found = 0;
    int cves_found = 0;
    int eol_kernels = 0;
};

// ============================================================================
// Utility Functions
// ============================================================================

std::string trim(const std::string& str) {
    auto start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::string escape_json(const std::string& s) {
    std::string result;
    for (char c : s) {
        switch (c) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default: result += c; break;
        }
    }
    return result;
}

std::string format_timestamp(int year, int month, int day) {
    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(4) << year 
        << "-" << std::setw(2) << (month < 10 ? '0' + month : month)
        << "-" << std::setw(2) << (day < 10 ? '0' + day : day);
    return oss.str();
}

bool is_kernel_eol(int year, int month) {
    for (const auto& eol : KERN_EOL_LIST) {
        if (year == eol.year && month >= std::stoi(eol.month)) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// Filesystem Traversal Core
// ============================================================================

class FileSystemTraverser {
public:
    fs::path root_path;
    CycloneDXBOM& bom;
    ScanResult& result;
    
    FileSystemTraverser(fs::path path, CycloneDXBOM& b, ScanResult& r) 
        : root_path(std::move(path)), bom(b), result(r) {}

    void traverse() {
        std::set<std::string> visited_dirs;
        int depth = 0;
        
        while (depth < MAX_DEPTH && !visited_dirs.empty()) {
            for (auto it = visited_dirs.begin(); it != visited_dirs.end(); ++it) {
                auto dir = root_path / *it;
                
                if (!fs::exists(dir)) continue;
                
                // Process files in this directory
                process_directory(dir, depth);
                
                // Add subdirectories to visit next level
                for (auto& entry : fs::directory_iterator(dir)) {
                    auto subdir = entry.is_directory() ? entry.path().filename() : "";
                    if (!subdir.empty()) {
                        visited_dirs.insert(subdir.string());
                    }
                }
            }
            
            // Clean up visited set for next iteration
            visited_dirs.clear();
            depth++;
        }
    }

private:
    void process_directory(const fs::path& dir, int current_depth) {
        result.total_files++;
        
        // Limit files per directory to prevent memory explosion
        if (result.total_files > MAX_FILES_PER_DIR * 100) {
            return;
        }
        
        // Check for package manifests first
        check_package_manifests(dir);
        
        // Scan regular files
        scan_regular_files(dir, current_depth);
    }

    void check_package_manifests(const fs::path& dir) {
        std::vector<std::string> manifest_patterns = {
            "control",      // Debian/Ubuntu .deb control file
            "packages.json",// Flatpak/Snap
            "manifest.xml",  // Various formats
            "pkglist.txt",   // Simple package lists
            "repo-manifest.json"
        };

        for (const auto& pattern : manifest_patterns) {
            fs::path manifest = dir / pattern;
            
            if (!fs::exists(manifest)) continue;
            
            parse_package_manifest(dir, manifest);
        }
    }

    void scan_regular_files(const fs::path& dir, int depth) {
        for (auto& entry : fs::directory_iterator(dir)) {
            auto file = entry.is_directory() ? "" : entry.path().filename();
            
            if (!file.empty()) {
                // Check for common config files that might contain package info
                if (is_config_file(file.string())) {
                    parse_config_file(entry);
                }
                
                // Check for source code with embedded dependencies
                if (entry.is_regular_file() && 
                    (file == "CMakeLists.txt" || file == "Makefile")) {
                    scan_build_files(entry, dir);
                }
            }
        }
    }

    bool is_config_file(const std::string& filename) {
        return filename.find(".config") != std::string::npos ||
               filename.find("settings.json") != std::string::npos ||
               filename.find("preferences.xml") != std::string::npos;
    }

    void parse_config_file(const fs::path& entry) {
        // Simple heuristic: look for version strings in config files
        auto content = read_file(entry);
        if (content.empty()) return;
        
        // Look for common version patterns
        std::regex ver_regex(R"(\b(v?)(\d{1,3}(\.\d{1,2})*)\b)");
        std::smatch match;
        
        while (std::regex_search(content, match, ver_regex)) {
            if (!match[1].str().empty()) { // Has 'v' prefix - more likely a version
                Component comp;
                comp.name = "config-" + filename(entry);
                comp.version = match[2].str();
                comp.type = "file";
                
                bom.addComponent(comp);
            }
            
            content = match.suffix().str();
        }
    }

    void scan_build_files(const fs::path& entry, const fs::path& parent) {
        auto content = read_file(entry);
        if (content.empty()) return;
        
        // Look for common dependency declarations
        std::vector<std::string> deps_found;
        
        // CMake dependencies
        if (entry.filename() == "CMakeLists.txt") {
            extract_cmake_deps(content, deps_found);
        }
        
        // Makefile dependencies
        else if (entry.filename() == "Makefile") {
            extract_makefile_deps(content, deps_found);
        }
        
        for (const auto& dep : deps_found) {
            Component comp;
            comp.name = parse_package_name(dep);
            comp.type = "library";
            bom.addComponent(comp);
        }
    }

    void extract_cmake_deps(const std::string& content, std::vector<std::string>& deps) {
        // Look for find_package calls
        std::regex cmake_find(R"(find_package\s*\(\s*([^)]+)\))");
        std::smatch match;
        
        while (std::regex_search(content, match, cmake_find)) {
            auto pkg = trim(match[1].str());
            if (!pkg.empty() && !pkg.starts_with("cmake")) {
                deps.push_back(pkg);
            }
            
            content = match.suffix().str();
        }
        
        // Look for add_subdirectory (indicates subproject dependencies)
        std::regex cmake_subdir(R"(add_subdirectory\s*\(\s*([^)]+)\))");
        while (std::regex_search(content, match, cmake_subdir)) {
            auto subdir = trim(match[1].str());
            if (!subdir.empty() && !subdir.starts_with("cmake")) {
                deps.push_back(subdir);
            }
            
            content = match.suffix().str();
        }
    }

    void extract_makefile_deps(const std::string& content, std::vector<std::string>& deps) {
        // Look for -l flags (libraries)
        std::regex make_lib(R"(-l\s*([^,\s]+))");
        std::smatch match;
        
        while (std::regex_search(content, match, make_lib)) {
            auto lib = trim(match[1].str());
            if (!lib.empty() && !lib.starts_with("-")) {
                deps.push_back(lib);
            }
            
            content = match.suffix().str();
        }
    }

    std::string parse_package_name(const std::string& raw) {
        // Remove common prefixes/suffixes
        auto clean = trim(raw);
        
        if (clean.starts_with("lib")) {
            clean = clean.substr(3);
        }
        
        if (clean.ends_with(".so") || clean.ends_with(".a")) {
            clean = clean.substr(0, clean.size() - 2);
        }
        
        return clean;
    }

    std::string filename(const fs::path& p) const {
        return p.filename().string();
    }

    std::string read_file(const fs::path& path) {
        if (!fs::exists(path)) return "";
        
        std::ifstream file(path, std::ios::binary);
        if (!file.is_open()) return "";
        
        std::ostringstream oss;
        oss << file.rdbuf();
        return oss.str();
    }

    void parse_package_manifest(const fs::path& dir, const fs::path& manifest) {
        auto content = read_file(manifest);
        if (content.empty()) return;
        
        // Parse based on manifest type
        std::string lower_name = to_lower(filename(manifest));
        
        if (lower_name.find("control") != std::string::npos) {
            parse_deb_control(dir, content);
        } else if (lower_name.find("packages.json") != std::string::npos ||
                   lower_name.find("manifest.json") != std::string::npos) {
            parse_json_manifest(content);
        } else if (lower_name.find("xml") != std::string::npos) {
            // Basic XML parsing for common patterns
            parse_xml_manifest(dir, content);
        }
    }

    void parse_deb_control(const fs::path& dir, const std::string& content) {
        // Parse Debian control file format
        std::map<std::string, std::string> fields;
        
        for (auto line : split_lines(content)) {
            auto pos = line.find('=');
            if (pos != std::string::npos) {
                auto key = trim(line.substr(0, pos));
                auto value = trim(line.substr(pos + 1));
                
                // Remove quotes from values
                if (!value.empty() && (value.front() == '"' || value.back() == '"')) {
                    value = value.substr(1);
                    if (value.size() > 1) value.pop_back();
                }
                
                fields[key] = value;
            }
        }
        
        // Extract package info
        std::string pkg_name = fields["Package"];
        std::string pkg_version = fields["Version"];
        
        if (!pkg_name.empty() && !pkg_version.empty()) {
            Component comp;
            comp.name = pkg_name;
            comp.version = pkg_version;
            comp.type = "library";
            
            // Try to determine hash from filename or content
            auto base_name = filename(manifest);
            if (base_name.find("control") != std::string::npos) {
                // Extract .deb file name for hash calculation
                auto deb_file = dir / ".." / ".." / "Packages";
                if (!fs::exists(deb_file)) {
                    deb_file = dir.parent_path() / "Packages";
                }
                
                if (fs::exists(deb_file)) {
                    // Calculate MD5 of the .deb file
                    auto md5 = calculate_md5(deb_file);
                    comp.hashes.push_back("md5:" + md5);
                }
            }
            
            bom.addComponent(comp);
        }
    }

    void parse_json_manifest(const std::string& content) {
        // Simple JSON parsing for common fields
        std::map<std::string, std::string> json_fields;
        
        // Look for "name" field
        auto name_pos = content.find("\"name\"");
        if (name_pos != std::string::npos) {
            auto start = content.find(':', name_pos);
            if (start != std::string::npos) {
                auto quote_start = content.find('"', start + 1);
                if (quote_start != std::string::npos) {
                    auto quote_end = content.find('"', quote_start + 1);
                    if (quote_end != std::string::npos) {
                        json_fields["name"] = content.substr(quote_start + 1, 
                            quote_end - quote_start - 1);
                    }
                }
            }
        }
        
        // Look for "version" field
        auto ver_pos = content.find("\"version\"");
        if (ver_pos != std::string::npos) {
            auto start = content.find(':', ver_pos);
            if (start != std::string::npos) {
                auto quote_start = content.find('"', start + 1);
                if (quote_start != std::string::npos) {
                    auto quote_end = content.find('"', quote_start + 1);
                    if (quote_end != std::string::npos) {
                        json_fields["version"] = content.substr(quote_start + 1, 
                            quote_end - quote_start - 1);
                    }
                }
            }
        }
        
        // Look for "type" field
        auto type_pos =