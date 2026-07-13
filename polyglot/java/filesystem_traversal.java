package polyglot.java;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;

/**
 * sbomb - Secure Bill of Materials Generator
 * 
 * Generates a CycloneDX SBOM from an unpacked firmware root filesystem,
 * flags components with known CVEs and EOL kernels.
 */
public class filesystem_traversal {

    // Configuration constants
    private static final String DEFAULT_ROOT_PATH = ".";
    private static final int MAX_DEPTH = 100;
    private static final long SCAN_TIMEOUT_MS = 30_000;
    
    // Known EOL kernel versions (format: "version -> end_date")
    private static final Map<String, LocalDate> KNOWN_EOL_KERNELS = 
        buildEolKernelMap();
    
    // Simulated CVE database for demo purposes
    private static final Set<String> KNOWN_CVE_COMPONENTS = 
        buildKnownCveComponents();

    public static void main(String[] args) {
        if (args.length == 0 || "--help".equals(args[0]) || "-h".equals(args[0])) {
            printUsage();
            return;
        }

        String rootPath = args.length > 0 ? args[0] : DEFAULT_ROOT_PATH;
        
        System.out.println("=== sbomb: Firmware SBOM Generator ===");
        System.out.println("Scanning: " + rootPath);
        System.out.println();

        try {
            // Step 1: Traversal and Discovery
            FirmwareScanner scanner = new FirmwareScanner(rootPath, MAX_DEPTH);
            Map<String, PackageInfo> packages = scanner.scanAllPackages();
            
            System.out.println("Discovered " + packages.size() + " package entries");
            System.out.println();

            // Step 2: CVE & EOL Analysis
            CveReport cveReport = CveChecker.analyze(packages.values());
            EolReport eolReport = KernelEolChecker.checkKernels(scanner.getKernelVersion());
            
            System.out.println("=== Security Flags ===");
            System.out.println();

            // Step 3: Generate CycloneDX SBOM
            CycloneDxBuilder builder = new CycloneDxBuilder();
            CycloneDxDocument sbom = builder.build(packages, cveReport, eolReport);
            
            String outputPath = "sbom.json";
            Files.writeString(Path.of(outputPath), 
                new JsonWriter(sbom).write());
            
            System.out.println("SBOM written to: " + outputPath);
            System.out.println();

            // Step 4: Summary Report
            printSummary(packages, cveReport, eolReport);

        } catch (Exception e) {
            System.err.println("Error during scan: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printUsage() {
        System.out.println("Usage: java filesystem_traversal [--root <path>]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  --root, -r <path>   Root directory to scan (default: current)");
        System.out.println("  --help, -h          Show this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java filesystem_traversal /tmp/firmware-extract");
        System.out.println("  java filesystem_traversal -r ./extracted-root");
    }

    /**
     * Main orchestrator for firmware scanning operations.
     */
    static class FirmwareScanner {
        private final String rootPath;
        private final int maxDepth;
        private String kernelVersion = "unknown";

        public FirmwareScanner(String rootPath, int maxDepth) {
            this.rootPath = rootPath;
            this.maxDepth = maxDepth;
        }

        /**
         * Recursively scans the filesystem for package metadata files.
         */
        Map<String, PackageInfo> scanAllPackages() throws IOException {
            Map<String, PackageInfo> packages = new LinkedHashMap<>();
            
            try (Stream<Path> walk = Files.walk(Path.of(rootPath))) {
                long startTime = System.currentTimeMillis();
                
                for (Path entry : walk) {
                    if (System.currentTimeMillis() - startTime > SCAN_TIMEOUT_MS) {
                        break;
                    }

                    // Skip non-regular files and symlinks pointing outside
                    if (!Files.isRegularFile(entry)) {
                        continue;
                    }

                    String relativePath = entry.getFileName().toString();
                    
                    // Detect package format and parse
                    PackageInfo info = detectAndParsePackage(entry, relativePath);
                    if (info != null) {
                        packages.put(relativePath, info);
                    }
                }
            }
            
            return packages;
        }

        /**
         * Extracts kernel version from common locations.
         */
        String getKernelVersion() {
            // Try /proc/version first (most reliable)
            try {
                String content = Files.readString(Path.of("/proc/version"));
                if (!content.isEmpty()) {
                    return extractKernelFromProc(content);
                }
            } catch (IOException e) {
                // Fall through to other methods
            }

            // Try /etc/os-release for distro-specific info
            try {
                String content = Files.readString(Path.of("/etc/os-release"));
                if (content.contains("PRETTY_NAME")) {
                    return extractDistroKernel(content);
                }
            } catch (IOException e) {
                // Continue with defaults
            }

            return kernelVersion;
        }

        /**
         * Extracts kernel version string from /proc/version output.
         */
        private String extractKernelFromProc(String content) {
            // Format: "Linux version 5.15.0-76-generic (gcc...) #84-Ubuntu"
            int spaceIndex = content.indexOf(' ');
            if (spaceIndex > 0) {
                return content.substring(spaceIndex + 1);
            }
            return "unknown";
        }

        /**
         * Extracts kernel info from /etc/os-release.
         */
        private String extractDistroKernel(String content) {
            // Look for patterns like "PRETTY_NAME=\"Ubuntu 22.04 LTS\""
            int quoteStart = content.indexOf('"');
            if (quoteStart > 0) {
                int quoteEnd = content.indexOf('"', quoteStart + 1);
                String prettyName = content.substring(quoteStart + 1, quoteEnd);
                
                // Try to extract version number
                int spaceIndex = prettyName.lastIndexOf(' ');
                if (spaceIndex > 0) {
                    return prettyName.substring(spaceIndex + 1).trim();
                }
            }
            return "unknown";
        }

        /**
         * Detects package format and parses metadata.
         */
        private PackageInfo detectAndParsePackage(Path path, String relativePath) {
            if (relativePath.endsWith(".deb")) {
                return parseDebFile(path);
            } else if (relativePath.endsWith(".rpm") || 
                       relativePath.endsWith(".rpmbuild")) {
                return parseRpmFile(path);
            } else if (relativePath.endsWith(".tar.gz") || 
                       relativePath.endsWith(".tgz") ||
                       relativePath.endsWith(".tar")) {
                return parseTarArchive(path);
            } else if (relativePath.equals("dpkg.status") || 
                       relativePath.contains("/var/lib/dpkg/status")) {
                return parseDpkgStatusFile(path);
            } else if (relativePath.contains("/var/lib/rpm/Packages")) {
                return parseRpmDatabase(path);
            }

            // Check for embedded package metadata in archives
            String name = path.getFileName().toString();
            if (name.toLowerCase().contains("package") || 
                name.toLowerCase().contains("lib") ||
                name.toLowerCase().contains("-dev")) {
                
                // Try to extract from tar archive
                try {
                    return parseTarArchive(path);
                } catch (IOException e) {
                    // Not a valid archive or extraction failed
                }
            }

            return null;
        }

        /**
         * Parses .deb files using dpkg-deb.
         */
        private PackageInfo parseDebFile(Path path) throws IOException {
            String controlData = extractControlData(path);
            
            if (controlData == null || controlData.isEmpty()) {
                return new PackageInfo("unknown", "deb", "", 
                    System.currentTimeMillis() / 1000, "");
            }

            // Parse control file fields
            Map<String, String> fields = parseControlFile(controlData);
            
            String name = fields.getOrDefault("Package", "unknown");
            String version = fields.getOrDefault("Version", "");
            String arch = fields.getOrDefault("Architecture", "all");
            long timestamp = System.currentTimeMillis() / 1000;
            
            // Extract maintainer email for contact info
            String maintainerEmail = extractMaintainerEmail(fields.get("Maintainer"));

            return new PackageInfo(name, "deb", arch, version, timestamp, 
                maintainerEmail);
        }

        /**
         * Parses .rpm files using rpmquery.
         */
        private PackageInfo parseRpmFile(Path path) throws IOException {
            // For RPMs, we'd typically use rpmquery command
            // This is a simplified implementation
            String name = "unknown";
            String version = "";
            
            try {
                ProcessBuilder pb = new ProcessBuilder(
                    "rpm", "-qp", "--qf", "%{NAME} %{VERSION}", path.toString()
                );
                Process process = pb.start();
                
                if (process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)) {
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream())
                    );
                    String line = reader.readLine();
                    if (line != null) {
                        String[] parts = line.split("\\s+");
                        name = parts[0];
                        version = parts.length > 1 ? parts[1] : "";
                    }
                }
            } catch (Exception e) {
                // Fall back to filename parsing
                String fileName = path.getFileName().toString();
                int lastDash = fileName.lastIndexOf('-');
                if (lastDash > 0) {
                    name = fileName.substring(0, lastDash);
                    version = fileName.substring(lastDash + 1);
                } else {
                    name = fileName;
                }
            }

            return new PackageInfo(name, "rpm", "noarch", 
                version.isEmpty() ? "unknown" : version,
                System.currentTimeMillis() / 1000, "");
        }

        /**
         * Parses tar archives for embedded packages.
         */
        private PackageInfo parseTarArchive(Path path) throws IOException {
            // Check if it's a compressed archive
            String fileName = path.getFileName().toString();
            
            ProcessBuilder pb;
            String[] commands;
            
            if (fileName.endsWith(".tar.gz") || fileName.endsWith(".tgz")) {
                commands = new String[]{"tar", "-tzf", path.toString()};
            } else if (fileName.endsWith(".tar")) {
                commands = new String[]{"tar", "-tf", path.toString()};
            } else {
                return null;
            }

            pb = new ProcessBuilder(commands);
            Process process = pb.start();
            
            // Read archive contents
            StringBuilder contents = new StringBuilder();
            try (BufferedReader reader = 
                     new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    contents.append(line).append('\n');
                }
            }

            if (!process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS)) {
                process.destroy();
            }

            // Look for common package metadata patterns
            String name = "unknown";
            String version = "";
            
            // Check for Debian control.tar.gz inside tar
            if (contents.toString().contains("control.tar")) {
                return parseDebFile(path);
            }

            // Check for RPM headers
            if (contents.toString().contains(".rpm")) {
                return parseRpmFile(path);
        }

            // Look for common package name patterns in archive contents
            String[] lines = contents.toString().split("\\n");
            for (String line : lines) {
                // Match patterns like "libfoo-1.2.3" or "foo-1.2.3-dev"
                if (line.matches("^[a-zA-Z0-9][-a-zA-Z0-9._]*-[0-9][^\\s]+")) {
                    String[] parts = line.split("-");
                    if (parts.length >= 2) {
                        name = parts[0];
                        version = parts[1];
                        break;
                    }
                }
            }

            return new PackageInfo(name, "tar", "unknown", 
                version.isEmpty() ? "unknown" : version,
                System.currentTimeMillis() / 1000, "");
        }

        /**
         * Parses dpkg status file for installed packages.
         */
        private PackageInfo parseDpkgStatusFile(Path path) throws IOException {
            String content = Files.readString(path);
            
            Map<String, String> fields = new HashMap<>();
            int currentField = -1;
            StringBuilder currentValue = new StringBuilder();

            for (int i = 0; i < content.length(); i++) {
                char c = content.charAt(i);
                
                if (c == '\n') {
                    if (currentField >= 0) {
                        fields.put(currentField, currentValue.toString());
                    }
                    currentField = -1;
                    currentValue.setLength(0);
                } else if (i > 0 && content.charAt(i-1) == ':') {
                    // New field starts after colon
                    int nextColon = content.indexOf(':', i + 1);
                    String fieldName = content.substring(i, nextColon).trim();
                    
                    switch (fieldName) {
                        case "Package": currentField = "name"; break;
                        case "Version": currentField = "version"; break;
                        case "Architecture": currentField = "arch"; break;
                        case "Maintainer": currentField = "maintainer"; break;
                    }
                } else if (currentField >= 0) {
                    currentValue.append(c);
                }
            }

            // Add last field
            if (currentField >= 0) {
                fields.put(currentField, currentValue.toString());
            }

            String name = fields.get("name");
            String version = fields.get("version");
            String arch = fields.get("arch");
            
            return new PackageInfo(
                name != null ? name : "unknown",
                "dpkg-status",
                arch != null ? arch : "unknown",
                version != null ? version : "",
                System.currentTimeMillis() / 1000,
                fields.get("maintainer")
            );
        }

        /**
         * Parses RPM database file.
         */
        private PackageInfo parseRpmDatabase(Path path) throws IOException {
            String content = Files.readString(path);
            
            // RPM Packages DB format: name|epoch|version|release|arch|...
            Map<String, String> fields = new HashMap<>();
            int currentField = -1;
            StringBuilder currentValue = new StringBuilder();

            for (int i = 0; i < content.length(); i++) {
                char c = content.charAt(i);
                
                if (c == '|' && currentField >= 0) {
                    fields.put(currentField, currentValue.toString());
                    currentField = -1;
                    currentValue.setLength(0);
                } else if (i > 0 && content.charAt(i-1) == '|') {
                    int nextPipe = content.indexOf('|', i + 1);
                    String fieldName = content.substring(i, nextPipe).trim();
                    
                    switch (fieldName) {
                        case "name": currentField = "name"; break;
                        case "epoch": currentField = "epoch"; break;
                        case "version": currentField = "version"; break;
                        case "release": currentField = "release"; break;
                        case "arch": currentField = "arch"; break;
                    }
                } else if (currentField >= 0) {
                    currentValue.append(c);
                }
            }

            // Combine name, version, release for full package identifier
            String name = fields.get("name");
            String version = fields.get("version");
            String release = fields.get("release");
            String arch = fields.get("arch");
            
            String fullName = (name != null) ? name : "unknown";
            if (version != null && !