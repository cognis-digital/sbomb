using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Reflection;
using System.Text.Json;
using System.Threading.Tasks;

namespace sbomb
{
    // =====================================================================
    // CORE DATA MODELS
    // =====================================================================

    /// <summary>
    /// Represents a discovered firmware component.
    /// </summary>
    public sealed class FirmwareComponent : IEquatable<FirmwareComponent>
    {
        public string Name { get; set; } = string.Empty;
        public string Version { get; set; } = string.Empty;
        public string Vendor { get; set; } = string.Empty;
        public string Type => "firmware"; // CycloneDX type for firmware
        public string SubType => "embedded";
        public string Purl { get; set; } = string.Empty;
        public List<string> Hashes { get; } = new();
        public Dictionary<string, string> Metadata { get; } = new();
        public bool IsEOLKernel { get; set; }
        public List<CVEEntry> KnownCVEs { get; } = new();

        public bool Equals(FirmwareComponent? other) =>
            Name == other?.Name && Version == other?.Version;

        public override int GetHashCode() => HashCode.Combine(Name, Version);

        public static FirmwareComponent Create(string name, string version, string vendor = "")
        {
            var purl = $"pkg:generic/{name}@{version}";
            return new FirmwareComponent
            {
                Name = name,
                Version = version,
                Vendor = vendor,
                Purl = purl
            };
        }

        public static FirmwareComponent CreateFromPkg(string pkgName, string pkgVersion)
        {
            var parts = pkgName.Split(new[] { '.', '_' }, StringSplitOptions.RemoveEmptyEntries);
            var name = parts.Length > 0 ? parts[0] : pkgName;
            var version = parts.Length > 1 && !string.IsNullOrEmpty(parts[1]) 
                ? parts[1].Split('v')[1] : "unknown";

            return Create(name, version);
        }
    }

    /// <summary>
    /// CVE entry from vulnerability database.
    /// </summary>
    public sealed class CVEEntry
    {
        public string ID { get; set; } = string.Empty;
        public int SeverityScore { get; set; } // CVSS 0-10
        public string Description { get; set; } = string.Empty;
        public DateTime PublishedDate { get; set; }

        public static CVEEntry Create(string id, double cvss)
        {
            return new CVEEntry
            {
                ID = id,
                SeverityScore = (int)Math.Round(cvss * 10),
                Description = $"Vulnerability {id} with CVSS {cvss:F2}",
                PublishedDate = DateTime.UtcNow
            };
        }
    }

    /// <summary>
    /// CycloneDX 1.4 SBOM document structure.
    /// </summary>
    public sealed class SBOMDocument
    {
        public string Version => "1.4";
        public string SchemaVersion => "1.4";
        public string Name => "sbomb-sbom";
        public string Vendor => "sbomb";
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public List<Components> Components { get; } = new();

        public static SBOMDocument Create()
        {
            return new SBOMDocument
            {
                SchemaVersion = "1.4",
                Name = "sbomb-sbom"
            };
        }

        public void AddComponent(FirmwareComponent component)
        {
            Components.Add(new Components
            {
                BOMRef = $"comp-{Guid.NewGuid():N}",
                Type = component.Type,
                SubType = component.SubType,
                Name = component.Name,
                Version = component.Version,
                Vendor = component.Vendor,
                Purl = component.Purl,
                Hashes = new List<Hash> { new Hash { Algorithm = "SHA-256", Value = string.Join(";", component.Hashes) } },
                ExternalReferences = new List<ExternalReference>
                {
                    new ExternalReference
                    {
                        Type = "cve",
                        Url = $"https://nvd.nist.gov/vuln/detail/{string.Join(";", component.KnownCVEs.Select(c => c.ID))}"
                    }
                },
                Properties = new List<Property>
                {
                    new Property { Name = "sbomb:eol", Value = component.IsEOLKernel ? "true" : "false" },
                    new Property { Name = "sbomb:cve_count", Value = component.KnownCVEs.Count.ToString() }
                }
            });
        }

        public string Serialize()
        {
            var options = new JsonSerializerOptions
            {
                WriteIndented = true,
                Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            return JsonSerializer.Serialize(this, options);
        }
    }

    /// <summary>
    /// CycloneDX component wrapper.
    /// </summary>
    public sealed class Components
    {
        [JsonPropertyName("bom-ref")]
        public string BOMRef { get; set; } = string.Empty;

        [JsonPropertyName("type")]
        public string Type { get; set; } = string.Empty;

        [JsonPropertyName("sub-type")]
        public string SubType { get; set; } = string.Empty;

        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("version")]
        public string Version { get; set; } = string.Empty;

        [JsonPropertyName("vendor")]
        public string Vendor { get; set; } = string.Empty;

        [JsonPropertyName("purl")]
        public string Purl { get; set; } = string.Empty;

        [JsonPropertyName("hashes")]
        public List<Hash> Hashes { get; set; } = new();

        [JsonPropertyName("external-refs")]
        public List<ExternalReference> ExternalReferences { get; set; } = new();

        [JsonPropertyName("properties")]
        public List<Property> Properties { get; set; } = new();
    }

    /// <summary>
    /// CycloneDX hash representation.
    /// </summary>
    public sealed class Hash
    {
        [JsonPropertyName("algorithm")]
        public string Algorithm { get; set; } = "SHA-256";

        [JsonPropertyName("value")]
        public string Value { get; set; } = string.Empty;
    }

    /// <summary>
    /// CycloneDX external reference.
    /// </summary>
    public sealed class ExternalReference
    {
        [JsonPropertyName("type")]
        public string Type { get; set; } = "cve";

        [JsonPropertyName("url")]
        public string Url { get; set; } = string.Empty;
    }

    /// <summary>
    /// CycloneDX property.
    /// </summary>
    public sealed class Property
    {
        [JsonPropertyName("name")]
        public string Name { get; set; } = string.Empty;

        [JsonPropertyName("value")]
        public string Value { get; set; } = string.Empty;
    }

    // =====================================================================
    // CORE SCANNER ORCHESTRATOR
    // =====================================================================

    /// <summary>
    /// Main firmware scanner that orchestrates all analysis tasks.
    /// </summary>
    public sealed class FirmwareScanner
    {
        private readonly string _rootPath;
        private readonly ConcurrentBag<FirmwareComponent> _components = new();
        private readonly List<CVEEntry> _cveDatabase = new();
        private readonly HashSet<string> _eolKernels = new();

        public IReadOnlyList<FirmwareComponent> Components => _components.AsReadOnly();
        public SBOMDocument SBOM { get; private set; } = SBOMDocument.Create();

        /// <summary>
        /// Creates a new scanner targeting the specified firmware root.
        /// </summary>
        public FirmwareScanner(string rootPath)
        {
            _rootPath = Path.GetFullPath(rootPath);
            InitializeCVEDatabase();
            LoadEOLKernelList();
        }

        /// <summary>
        /// Entry point: scans the entire firmware filesystem.
        /// </summary>
        public async Task<SBOMDocument> ScanAsync()
        {
            var watch = new Stopwatch();
            watch.Start();

            // Phase 1: Traverse and discover packages
            await DiscoverPackagesAsync();

            // Phase 2: Analyze binaries for embedded libraries
            AnalyzeBinaries();

            // Phase 3: Check kernel version against EOL list
            CheckKernelVersion();

            // Phase 4: Match components against CVE database
            MatchCVEs();

            watch.Stop();

            Console.WriteLine($"Scan complete in {watch.ElapsedMilliseconds}ms");
            Console.WriteLine($"Discovered {_components.Count} components");

            return SBOM;
        }

        private async Task DiscoverPackagesAsync()
        {
            var tasks = new[]
            {
                ScanDebsAsync(),
                ScanRpmAsync(),
                ScanApkAsync(),
                ScanPipAsync(),
                ScanNpmAsync(),
                ScanMavenAsync()
            };

            await Task.WhenAll(tasks);
        }

        private async Task ScanDebsAsync()
        {
            var dpkgData = Path.Combine(_rootPath, "var", "lib", "dpkg");
            if (!Directory.Exists(dpkgData)) return;

            // Parse dpkg status file for installed packages
            var statusFile = Path.Combine(dpkgData, "status");
            if (File.Exists(statusFile))
            {
                await using var reader = new StreamReader(statusFile);
                while (reader.ReadLine() is string line)
                {
                    var parts = line.Split(new[] { ' ', '\t' }, 4, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && !string.IsNullOrEmpty(parts[1]))
                    {
                        _components.Add(FirmwareComponent.CreateFromPkg(
                            parts[0], 
                            parts[1]
                        ));
                    }
                }
            }

            // Also scan .deb files for embedded libraries
            var debFiles = Directory.GetFiles(dpkgData, "*.deb");
            foreach (var file in debFiles)
            {
                await ExtractAndAnalyzeDebAsync(file);
            }
        }

        private async Task ScanRpmAsync()
        {
            var rpmDir = Path.Combine(_rootPath, "usr", "share", "rpm");
            if (!Directory.Exists(rpmDir)) return;

            // Parse RPM database header
            var dbHeader = Path.Combine(rpmDir, "db.hdr");
            if (File.Exists(dbHeader))
            {
                await using var reader = new StreamReader(dbHeader);
                while (reader.ReadLine() is string line)
                {
                    var parts = line.Split(new[] { ' ', '\t' }, 4, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && !string.IsNullOrEmpty(parts[1]))
                    {
                        _components.Add(FirmwareComponent.CreateFromPkg(
                            parts[0], 
                            parts[1]
                        ));
                    }
                }
            }

            // Scan .rpm files for embedded libraries
            var rpmFiles = Directory.GetFiles(rpmDir, "*.rpm");
            foreach (var file in rpmFiles)
            {
                await ExtractAndAnalyzeRpmAsync(file);
            }
        }

        private async Task ScanApkAsync()
        {
            // Android APK packages - scan for embedded libraries
            var apkLibs = Directory.EnumerateFiles(_rootPath, "*.so")
                .Where(p => p.EndsWith(".so", StringComparison.OrdinalIgnoreCase))
                .Take(100) // Limit to avoid memory issues on large images
                .ToList();

            foreach (var lib in apkLibs)
            {
                var name = Path.GetFileNameWithoutExtension(lib).Replace(".so.", "");
                _components.Add(FirmwareComponent.Create(name, "unknown", "Android"));
            }
        }

        private async Task ScanPipAsync()
        {
            // Python pip packages - check requirements.txt and site-packages
            var sitePackages = Path.Combine(_rootPath, "usr", "lib", "python");
            
            if (Directory.Exists(sitePackages))
            {
                foreach (var pkgDir in Directory.EnumerateDirectories(sitePackages, "*", SearchOption.AllDirectories)
                                         .Where(d => d.Contains("site-packages")))
                {
                    var pkgName = Path.GetFileName(pkgDir);
                    _components.Add(FirmwareComponent.CreateFromPkg(pkgName, "unknown"));
                }
            }

            // Also check requirements.txt files
            var reqFiles = Directory.EnumerateFiles(_rootPath, "*.txt")
                .Where(f => f.Contains("requirements", StringComparison.OrdinalIgnoreCase));

            foreach (var file in reqFiles)
            {
                await using var reader = new StreamReader(file);
                while (reader.ReadLine() is string line && !string.IsNullOrWhiteSpace(line))
                {
                    if (!line.StartsWith("#"))
                    {
                        _components.Add(FirmwareComponent.CreateFromPkg(
                            line.Split(' ', '\t')[0].Trim(), 
                            "unknown"
                        ));
                    }
                }
            }
        }

        private async Task ScanNpmAsync()
        {
            // Node.js npm packages - check package.json files
            var pkgJsonFiles = Directory.EnumerateFiles(_rootPath, "*.json")
                .Where(f => f.Contains("package.json", StringComparison.OrdinalIgnoreCase));

            foreach (var file in pkgJsonFiles)
            {
                await using var reader = new StreamReader(file);
                while (reader.ReadLine() is string line && !string.IsNullOrWhiteSpace(line))
                {
                    if (!line.StartsWith("//") && !line.StartsWith("#"))
                    {
                        _components.Add(FirmwareComponent.CreateFromPkg(
                            line.Split(' ', '\t')[0].Trim(), 
                            "unknown"
                        ));
                    }
                }
            }
        }

        private async Task ScanMavenAsync()
        {
            // Maven packages - check pom.xml files
            var pomFiles = Directory.EnumerateFiles(_rootPath, "*.xml")
                .Where(f => f.Contains("pom.xml", StringComparison.OrdinalIgnoreCase));

            foreach (var file in pomFiles)
            {
                await using var reader = new StreamReader(file);
                while (reader.ReadLine() is string line && !string.IsNullOrWhiteSpace(line))
                {
                    if (!line.StartsWith("<!--") && !line.StartsWith("</"))
                    {
                        _components.Add(FirmwareComponent.CreateFromPkg(
                            line.Split(' ', '\t')[0].Trim(), 
                            "unknown"
                        ));
                    }
                }
            }
        }

        private async Task ExtractAndAnalyzeDebAsync(string debPath)
        {
            // Simple extraction - in production, use dpkg-deb or libarchive
            var tempDir = Path.Combine(Path.GetTempPath(), $"sbomb-{Guid.NewGuid():N}");
            
            try
            {
                await using (var archive = new ZipArchive(await File.OpenRead(debPath)))
                {
                    foreach (var entry in archive.Entries)
                    {
                        if (!string.IsNullOrEmpty(entry.Name))
                        {
                            var name = Path.GetFileNameWithoutExtension(entry.Name);
                            _components.Add(FirmwareComponent.CreateFromPkg(name, "unknown"));
                        }
                    }
                }
            }
            finally
            {
                // Cleanup temp directory (async delete)
                if (Directory.Exists(tempDir))
                {
                    await Task.Run(() => Directory.Delete(tempDir, true));
                }
            }
        }

        private async Task ExtractAndAnalyzeRpmAsync(string rpmPath)
        {
            // RPM uses a different format - simplified extraction
            var tempDir = Path.Combine(Path.GetTempPath(), $"sbomb-{Guid.NewGuid():N}");
            
            try
            {
                await using (var archive = new ZipArchive(await File.OpenRead(rpmPath)))
                {
                    foreach (var entry in archive.Entries)
                    {
                        if (!string.IsNullOrEmpty(entry.Name))
                        {
                            var name = Path.GetFileNameWithoutExtension(entry.Name);
                            _components.Add(FirmwareComponent.CreateFromPkg(name, "unknown"));