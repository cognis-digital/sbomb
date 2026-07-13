/*
 * sbomb - Security Bill of Materials Generator
 * 
 * A complete CycloneDX SBOM generator for unpacked firmware root filesystems.
 * Scans directories recursively, parses common package formats, matches CVEs/EOL,
 * and outputs standard CycloneDX JSON format.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <time.h>

/* ============================================================================
 * CONFIGURATION
 */

#define MAX_PATH_LEN    4096
#define MAX_COMPONENTS  1024
#define MAX_VULNS_PER_COMP 32
#define MAX_DEPS_PER_COMP   64
#define DEFAULT_ROOT_DIR "."
#define DEFAULT_OUTPUT_FILE "sbom.json"

/* CycloneDX version */
#define CXD_VERSION    "1.5"

/* ============================================================================
 * TYPES AND DATA STRUCTURES
 */

typedef enum {
    PKG_TYPE_UNKNOWN,
    PKG_TYPE_DEB,
    PKG_TYPE_RPM,
    PKG_TYPE_TAR,
    PKG_TYPE_GENERIC
} PackageType;

typedef struct {
    char name[256];
    char version[128];
    PackageType type;
    char path[MAX_PATH_LEN];
    char arch[32];
    char maintainer[256];
    char license[256];
    time_t timestamp;
    struct {
        char name[256];
        char version[128];
    } dependencies[64];
} Package;

typedef enum {
    CVE_SEV_UNKNOWN,
    CVE_SEV_LOW,
    CVE_SEV_MEDIUM,
    CVE_SEV_HIGH,
    CVE_SEV_CRITICAL
} Cveseverity;

typedef struct {
    char cve_id[128];
    Cveseverity severity;
    char description[512];
    char affected_version[64];
    char fixed_version[64];
    time_t published_date;
} Vulnerability;

typedef enum {
    KERNEL_EOL_UNKNOWN,
    KERNEL_EOL_ACTIVE,
    KERNEL_EOL_WARNING,
    KERNEL_EOL_CRITICAL
} KernelEolStatus;

typedef struct {
    char kernel_name[256];
    char version[128];
    time_t release_date;
    time_t eol_date;
    int years_to_eol;
    KernelEolStatus status;
} EOLKernel;

/* ============================================================================
 * GLOBAL STATE
 */

static Package packages[MAX_COMPONENTS] = {0};
static int package_count = 0;
static Vulnerability vulnerabilities[MAX_COMPONENTS * MAX_VULNS_PER_COMP];
static int vuln_count = 0;
static char root_dir[MAX_PATH_LEN] = DEFAULT_ROOT_DIR;
static char output_file[MAX_PATH_LEN] = DEFAULT_OUTPUT_FILE;

/* ============================================================================
 * UTILITY FUNCTIONS
 */

static void trim_whitespace(char *str) {
    while (*str == ' ' || *str == '\t' || *str == '\n') str++;
    if (*str == 0) return;
    
    char *end = str + strlen(str) - 1;
    while (end > str && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    *(end + 1) = 0;
}

static void sanitize_filename(char *dest, const char *src, size_t max_len) {
    strncpy(dest, src, max_len - 1);
    dest[max_len - 1] = 0;
    
    /* Remove problematic characters */
    for (size_t i = 0; i < strlen(dest); i++) {
        if (dest[i] == '/' || dest[i] == '\\' || dest[i] == ':' || 
            dest[i] == '?' || dest[i] == '*' || dest[i] == '"' ||
            dest[i] == '<' || dest[i] == '>' || dest[i] == '|' ||
            dest[i] == 0) {
            dest[i] = '_';
        }
    }
}

static int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

/* ============================================================================
 * FILESYSTEM TRAVERSAL (Main Capability)
 */

typedef struct TraverseState {
    PackageType detected_type;
    char extracted_path[MAX_PATH_LEN];
    int extraction_complete;
} TraverseState;

static TraverseState traverse_states[MAX_COMPONENTS] = {0};

static void init_traverse_state(TraverseState *state, const char *path) {
    state->detected_type = PKG_TYPE_UNKNOWN;
    strncpy(state->extracted_path, path, MAX_PATH_LEN - 1);
    state->extraction_complete = 0;
}

/* Check if directory is a package archive */
static int is_package_archive(const char *path) {
    const char *exts[] = {".deb", ".rpm", ".tar.gz", ".tgz", 
                          ".tar.bz2", ".tbz2", ".tar.xz", ".txz",
                          ".deb.tar.gz", NULL};
    
    for (int i = 0; exts[i]; i++) {
        if (strstr(path, exts[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

/* Check if path is a directory containing extracted packages */
static int is_extracted_root(const char *path) {
    DIR *dir = opendir(path);
    if (!dir) return 0;
    
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Check for common package directories in extracted archives */
        const char *dirs[] = {"control", "var/lib/dpkg/status", 
                              "rpmdb", ".packages", "Packages",
                              "dpkg_status", NULL};
        
        for (int i = 0; dirs[i]; i++) {
            if (strstr(entry->d_name, dirs[i]) != NULL) {
                closedir(dir);
                return 1;
            }
        }
    }
    
    closedir(dir);
    return 0;
}

/* Recursively traverse filesystem and collect packages */
static int traverse_directory(const char *dir_path, TraverseState *state) {
    DIR *dp = opendir(dir_path);
    if (!dp) {
        fprintf(stderr, "Error opening directory %s: %s\n", dir_path, strerror(errno));
        return -1;
    }
    
    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        char full_path[MAX_PATH_LEN];
        snprintf(full_path, MAX_PATH_LEN, "%s/%s", dir_path, entry->d_name);
        
        /* Check if this is a package archive */
        if (is_package_archive(entry->d_name)) {
            init_traverse_state(state, full_path);
            
            /* Determine type from extension */
            const char *ext = strrchr(full_path, '.');
            if (strstr(ext, ".deb")) {
                state->detected_type = PKG_TYPE_DEB;
            } else if (strstr(ext, ".rpm")) {
                state->detected_type = PKG_TYPE_RPM;
            } else if (strstr(ext, ".tar") || strstr(ext, ".gz")) {
                state->detected_type = PKG_TYPE_TAR;
            } else {
                state->detected_type = PKG_TYPE_GENERIC;
            }
            
            /* Mark as found */
            strncpy(state->extracted_path, full_path, MAX_PATH_LEN - 1);
            state->extraction_complete = 1;
        }
        
        /* Check if this is an extracted root directory */
        else if (is_extracted_root(entry->d_name)) {
            init_traverse_state(state, full_path);
            strncpy(state->extracted_path, full_path, MAX_PATH_LEN - 1);
            state->extraction_complete = 1;
        }
        
        /* Recursively traverse subdirectories */
        else if (entry->d_type == DT_DIR) {
            int result = traverse_directory(full_path, state);
            if (result < 0 && !state->extraction_complete) {
                return -1;
            }
        }
    }
    
    closedir(dp);
    return 0;
}

/* ============================================================================
 * DEB PACKAGE PARSER
 */

static int parse_deb_control(const char *control_path, Package *pkg) {
    FILE *fp = fopen(control_path, "r");
    if (!fp) return -1;
    
    pkg->type = PKG_TYPE_DEB;
    pkg->timestamp = time(NULL);
    
    /* Parse fields */
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        trim_whitespace(line);
        
        if (strncmp(line, "Package:", 8) == 0) {
            strncpy(pkg->name, line + 8, sizeof(pkg->name) - 1);
        } else if (strncmp(line, "Version:", 8) == 0) {
            strncpy(pkg->version, line + 8, sizeof(pkg->version) - 1);
        } else if (strncmp(line, "Architecture:", 13) == 0) {
            strncpy(pkg->arch, line + 13, sizeof(pkg->arch) - 1);
        } else if (strncmp(line, "Maintainer:", 11) == 0) {
            strncpy(pkg->maintainer, line + 11, sizeof(pkg->maintainer) - 1);
        } else if (strncmp(line, "License:", 8) == 0) {
            strncpy(pkg->license, line + 8, sizeof(pkg->license) - 1);
        }
    }
    
    fclose(fp);
    return 0;
}

static int parse_deb_status(const char *status_path, Package *pkg) {
    FILE *fp = fopen(status_path, "r");
    if (!fp) return -1;
    
    pkg->type = PKG_TYPE_DEB;
    pkg->timestamp = time(NULL);
    
    /* Parse dpkg status file */
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        trim_whitespace(line);
        
        if (strncmp(line, "Package:", 8) == 0) {
            strncpy(pkg->name, line + 8, sizeof(pkg->name) - 1);
        } else if (strncmp(line, "Version:", 8) == 0) {
            strncpy(pkg->version, line + 8, sizeof(pkg->version) - 1);
        } else if (strncmp(line, "Architecture:", 13) == 0) {
            strncpy(pkg->arch, line + 13, sizeof(pkg->arch) - 1);
        }
    }
    
    fclose(fp);
    return 0;
}

/* ============================================================================
 * RPM PACKAGE PARSER
 */

static int parse_rpm_db(const char *db_path, Package *pkg) {
    /* Simple parsing of rpm database header */
    FILE *fp = fopen(db_path, "r");
    if (!fp) return -1;
    
    pkg->type = PKG_TYPE_RPM;
    pkg->timestamp = time(NULL);
    
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        trim_whitespace(line);
        
        /* Look for Package: or Name: fields */
        if (strncmp(line, "Package:", 8) == 0 || 
            strncmp(line, "Name:", 5) == 0) {
            strncpy(pkg->name, line + 6, sizeof(pkg->name) - 1);
        } else if (strncmp(line, "Version:", 8) == 0) {
            strncpy(pkg->version, line + 8, sizeof(pkg->version) - 1);
        } else if (strncmp(line, "Arch:", 5) == 0) {
            strncpy(pkg->arch, line + 5, sizeof(pkg->arch) - 1);
        }
    }
    
    fclose(fp);
    return 0;
}

/* ============================================================================
 * GENERIC TAR ARCHIVE SCANNER
 */

static int scan_tar_archive(const char *archive_path, Package *pkg) {
    pkg->type = PKG_TYPE_TAR;
    strncpy(pkg->path, archive_path, MAX_PATH_LEN - 1);
    pkg->timestamp = time(NULL);
    
    /* Check for common package indicators inside tar */
    FILE *fp = fopen(archive_path, "r");
    if (!fp) return -1;
    
    char line[4096];
    while (fgets(line, sizeof(line), fp)) {
        trim_whitespace(line);
        
        /* Check for package metadata files */
        if (strstr(line, "control.tar") || 
            strstr(line, "debian-binary") ||
            strstr(line, "rpmheader") ||
            strstr(line, ".packages")) {
            
            /* Found a tar archive with package contents */
            pkg->detected_type = PKG_TYPE_TAR;
        } else if (strstr(line, "Package:") || strstr(line, "Name:")) {
            strncpy(pkg->name, line, 256);
        }
    }
    
    fclose(fp);
    return 0;
}

/* ============================================================================
 * KERNEL EOL DETECTION
 */

static int parse_kernel_version(const char *version_str, char *out_buf, size_t buf_size) {
    /* Parse version like "5.15.0-76-generic" or "4.19.123" */
    strncpy(out_buf, version_str, buf_size - 1);
    
    /* Extract numeric portion for comparison */
    const char *num = strstr(version_str, "-");
    if (num) {
        num++;
    } else {
        num = version_str;
    }
    
    return 0;
}

static int compare_kernel_versions(const char *v1, const char *v2) {
    /* Simple string-based comparison for common formats */
    if (strcmp(v1, v2) == 0) return 0;
    
    /* Extract numeric parts */
    char num1[64], num2[64];
    strncpy(num1, v1, sizeof(num1) - 1);
    strncpy(num2, v2, sizeof(num2) - 1);
    
    const char *sep1 = strchr(v1, '-');
    const char *sep2 = strchr(v2, '-');
    
    if (sep1 && sep2) {
        size_t len1 = sep1 - v1;
        size_t len2 = sep2 - v2;
        
        if (len1 < sizeof(num1)) strncpy(num1, v1, len1);
        if (len2 < sizeof(num2)) strncpy(num2, v2, len2);
    } else {
        strncpy(num1, v1, 64);
        strncpy(num2, v2, 64);
    }
    
    return strcmp(num1, num2);
}

/* Known EOL kernel versions (Linux LTS releases) */
static const char *lts_kernels[] = {
    "3.10", "3.16", "4.1", "4.4", "4.9", 
    "5.4", "5.10", "5.15", "6.1", NULL
};

static int check_kernel_eol(const char *kernel_version, EOLKernel *eol) {
    eol->status = KERNEL_EOL_UNKNOWN;
    eol->release_date = time(NULL);
    eol->eol_date = 0;
    
    /* Check against known LTS releases */
    for (int i = 0; lts_kernels[i]; i++) {
        if (strncmp(kernel_version, lts_kernels[i], strlen(lts_kernels[i])) == 0) {
            /* Approximate release dates for LTS kernels */
            int year_offset[] = {-12, -8, -4, 0, 4, 
                                 8, 12, 16, 20, 24};
            
            eol->release_date += (year_offset[i