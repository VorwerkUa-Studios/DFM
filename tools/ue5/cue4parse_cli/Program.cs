using System.Buffers.Binary;
using System.Text.Json;
using CUE4Parse.Compression;
using CUE4Parse.Encryption.Aes;
using CUE4Parse.UE4.Assets.Exports;
using CUE4Parse.FileProvider;
using CUE4Parse.MappingsProvider;
using CUE4Parse.UE4.Assets;
using CUE4Parse.UE4.Objects.Core.Misc;
using CUE4Parse.UE4.Versions;

string? temporaryMappingsPath = null;

if (args.Length != 8)
{
    Console.Error.WriteLine("Usage: Decod.Cue4Parse <paks-dir> <output-json> <game-version> <filter> <limit> <probe-asset> <package-type> <extract-dir>");
    return 2;
}

try
{
    var paksDirectory = Path.GetFullPath(args[0]);
    var outputPath = Path.GetFullPath(args[1]);
    var gameVersionName = args[2];
    var filter = args[3];
    var limit = int.Parse(args[4]);
    var probeAsset = args[5];
    var packageType = args[6].ToLowerInvariant();
    var extractDirectory = args[7];

    if (!Directory.Exists(paksDirectory))
        throw new DirectoryNotFoundException($"IoStore/PAK directory not found: {paksDirectory}");
    if (limit < 1 || limit > 100_000)
        throw new ArgumentOutOfRangeException(nameof(limit), "Limit must be between 1 and 100000.");
    if (packageType is not ("all" or "maps" or "assets"))
        throw new ArgumentException("Package type must be all, maps, or assets.");
    if (!Enum.TryParse<EGame>(gameVersionName, true, out var gameVersion))
        throw new ArgumentException($"Unsupported CUE4Parse game version: {gameVersionName}");

    var oodlePath = FindOodlePath(paksDirectory);
    if (oodlePath is not null)
        OodleHelper.Initialize(oodlePath);

    var gameRoot = Path.GetFullPath(Path.Combine(paksDirectory, "..", ".."));
    var isStalker2 = string.Equals(Path.GetFileName(gameRoot), "Stalker2", StringComparison.OrdinalIgnoreCase);
    if (isStalker2)
    {
        ObjectTypeRegistry.RegisterClass("InstancedStaticMeshComponent", typeof(Stalker2InstancedStaticMeshComponent));
        ObjectTypeRegistry.RegisterClass("BakedFoliageActor", typeof(Stalker2BakedFoliageActor));
    }

    var versionContainer = new VersionContainer(gameVersion);

    using var provider = new DefaultFileProvider(
        paksDirectory,
        SearchOption.TopDirectoryOnly,
        true,
        versionContainer);

    var mappingsPath = FindMappingsPath(paksDirectory);
    string? mappingsCompatibility = null;
    if (!string.IsNullOrWhiteSpace(mappingsPath))
    {
        var providerMappingsPath = PrepareMappingsPath(mappingsPath, out mappingsCompatibility);
        if (!string.Equals(providerMappingsPath, mappingsPath, StringComparison.OrdinalIgnoreCase))
            temporaryMappingsPath = providerMappingsPath;
        provider.MappingsContainer = new FileUsmapTypeMappingsProvider(providerMappingsPath);
    }

    provider.Initialize();
    var aesKey = Environment.GetEnvironmentVariable("DECOD_CUE4PARSE_AES_KEY");
    if (!string.IsNullOrWhiteSpace(aesKey))
        provider.SubmitKey(new FGuid(), new FAesKey(aesKey));
    var mountsAdded = provider.Mount();
    var mountedVfsCount = provider.MountedVfs.Count;
    var registeredVfsCount = provider.MountedVfs.Count + provider.UnloadedVfs.Count;
    var unloadedVfs = provider.UnloadedVfs
        .Select(vfs => new
        {
            name = vfs.Name,
            path = vfs.Path,
            encrypted = vfs.IsEncrypted,
            has_directory_index = vfs.HasDirectoryIndex
        })
        .ToArray();
    var requiredKeys = provider.RequiredKeys.Select(key => key.ToString()).ToArray();

    var packagePaths = provider.Files.Values
        .Select(file => file.Path)
        .Concat(provider.FilesById.Values.Select(file => file.Path))
        .Where(path => path.EndsWith(".uasset", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".umap", StringComparison.OrdinalIgnoreCase))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
        .ToArray();
    IEnumerable<string> selectedPackagePaths = packageType switch
    {
        "maps" => packagePaths.Where(path => path.EndsWith(".umap", StringComparison.OrdinalIgnoreCase)),
        "assets" => packagePaths.Where(path => path.EndsWith(".uasset", StringComparison.OrdinalIgnoreCase)),
        _ => packagePaths
    };
    var matchingPaths = string.IsNullOrWhiteSpace(filter)
        ? selectedPackagePaths.ToArray()
        : selectedPackagePaths.Where(path => path.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToArray();
    var matches = matchingPaths.Take(limit).ToArray();
    var scanStatus = packagePaths.Length > 0 ? "success" : "partial";

    object? probe = null;
    string? probeStatus = null;
    if (probeAsset.StartsWith("@batch:", StringComparison.Ordinal))
    {
        if (string.IsNullOrWhiteSpace(extractDirectory))
            throw new ArgumentException("Batch probes require an extraction directory.");
        var batchManifestPath = Path.GetFullPath(probeAsset["@batch:".Length..]);
        var batchAssets = JsonSerializer.Deserialize<string[]>(File.ReadAllText(batchManifestPath))
            ?? throw new InvalidDataException("Batch probe manifest must contain a JSON array of package paths.");
        if (batchAssets.Length == 0 || batchAssets.Any(string.IsNullOrWhiteSpace))
            throw new ArgumentException("Batch probe manifest must contain at least one non-empty package path.");

        var reportsDirectory = outputPath + ".probes";
        Directory.CreateDirectory(reportsDirectory);
        var batchResults = new List<object>(batchAssets.Length);
        var batchStatuses = new List<string>(batchAssets.Length);
        for (var index = 0; index < batchAssets.Length; index++)
        {
            var result = ProbePackage(provider, batchAssets[index], extractDirectory);
            batchStatuses.Add(result.Status);
            var reportPath = Path.Combine(reportsDirectory, $"{index:D6}_{SanitizeFileName(result.Package)}.json");
            var probeReport = new
            {
                format = "decod-cue4parse-probe-v1",
                game_version = gameVersion.ToString(),
                mappings_path = mappingsPath,
                mappings_compatibility = mappingsCompatibility,
                probe = result.Report
            };
            File.WriteAllText(reportPath, JsonSerializer.Serialize(
                probeReport,
                new JsonSerializerOptions { WriteIndented = true }));
            batchResults.Add(new
            {
                package = result.Package,
                status = result.Status,
                report = reportPath
            });
        }

        probeStatus = batchStatuses.All(status => status == "parsed")
            ? "parsed"
            : batchStatuses.Any(status => status is "parsed" or "partial") ? "partial" : "error";
        probe = new
        {
            status = probeStatus,
            report_directory = reportsDirectory,
            package_count = batchAssets.Length,
            parsed_count = batchStatuses.Count(status => status == "parsed"),
            partial_count = batchStatuses.Count(status => status == "partial"),
            raw_only_count = batchStatuses.Count(status => status == "raw_only"),
            error_count = batchStatuses.Count(status => status == "error"),
            probes = batchResults
        };
    }
    else if (!string.IsNullOrWhiteSpace(probeAsset))
    {
        var result = ProbePackage(provider, probeAsset, extractDirectory);
        probeStatus = result.Status;
        probe = result.Report;
    }

    var report = new
    {
        format = "decod-cue4parse-iostore-index-v1",
        status = scanStatus,
        paks_directory = paksDirectory,
        extraction_directory = string.IsNullOrWhiteSpace(extractDirectory) ? null : Path.GetFullPath(extractDirectory),
        game_version = gameVersion.ToString(),
        mounts_added = mountsAdded,
        registered_vfs_count = registeredVfsCount,
        mounted_vfs_count = mountedVfsCount,
        unloaded_vfs_count = provider.UnloadedVfs.Count,
        unloaded_vfs = unloadedVfs,
        required_aes_keys = requiredKeys,
        registered_file_count = provider.Files.Count + provider.FilesById.Count,
        package_count = packagePaths.Length,
        matching_package_count = matchingPaths.Length,
        returned_package_count = matches.Length,
        truncated = matchingPaths.Length > matches.Length,
        package_type = packageType,
        filter,
        categories = new
        {
            maps = packagePaths.Count(path => path.EndsWith(".umap", StringComparison.OrdinalIgnoreCase)),
            landscapes = packagePaths.Count(path => path.Contains("landscape", StringComparison.OrdinalIgnoreCase)
                || path.Contains("terrain", StringComparison.OrdinalIgnoreCase)),
            world_partition = packagePaths.Count(path => path.Contains("worldpartition", StringComparison.OrdinalIgnoreCase)),
            meshes = packagePaths.Count(path => path.Contains("staticmesh", StringComparison.OrdinalIgnoreCase)
                || path.Contains("static_mesh", StringComparison.OrdinalIgnoreCase))
        },
        packages = matches,
        probe,
        oodle_configured = oodlePath is not null,
        oodle_path = oodlePath,
        mappings_configured = !string.IsNullOrWhiteSpace(mappingsPath),
        mappings_path = mappingsPath,
        mappings_compatibility = mappingsCompatibility,
        aes_key_configured = !string.IsNullOrWhiteSpace(aesKey),
        notes = new[]
        {
            "Package-name classification is based on paths and names; verify candidate assets before conversion.",
            "Mappings are auto-discovered in the game root, Binaries/Win64, and Binaries/Win64/ue4ss; DECOD_CUE4PARSE_USMAP overrides discovery.",
            "GAME_UE5_5 matches the installed UE 5.5 build; GAME_Stalker2 in this CUE4Parse version uses an older engine profile.",
            "UE4SS USMAP v4 is converted to CUE4Parse v3 in a temporary copy; explicit enum values are omitted.",
            "STALKER 2 instanced-mesh readers check declared array sizes against export bounds and report truncated payloads.",
            "Asset parsing may require the game's AES key and a matching .usmap file."
        }
    };

    Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
    var json = JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true });
    File.WriteAllText(outputPath, json);
    Console.WriteLine(JsonSerializer.Serialize(new
    {
        status = scanStatus,
        output = outputPath,
        package_count = packagePaths.Length,
        matching_package_count = matchingPaths.Length,
        returned_package_count = matches.Length,
        registered_vfs_count = registeredVfsCount,
        mounted_vfs_count = mountedVfsCount,
        unloaded_vfs_count = provider.UnloadedVfs.Count,
        required_aes_keys = requiredKeys,
        oodle_configured = oodlePath is not null,
        truncated = matchingPaths.Length > matches.Length,
        package_type = packageType,
        probe_status = probeStatus,
        probe,
        mappings_compatibility = mappingsCompatibility
    }));
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(JsonSerializer.Serialize(new
    {
        status = "error",
        type = error.GetType().Name,
        message = error.Message
    }));
    return 1;
}
finally
{
    if (temporaryMappingsPath is not null && File.Exists(temporaryMappingsPath))
        File.Delete(temporaryMappingsPath);
}

static string PrepareMappingsPath(string sourcePath, out string compatibility)
{
    var data = File.ReadAllBytes(sourcePath);
    if (data.Length < 16)
        throw new InvalidDataException("USMAP file is shorter than its header.");

    var version = data[2];
    if (version < 4)
    {
        compatibility = "native";
        return sourcePath;
    }
    if (version > 4)
        throw new NotSupportedException($"USMAP version {version} is not supported by the .NET 8 CUE4Parse package.");

    var converted = ConvertUsmapV4ToV3(data);
    var temporaryPath = Path.Combine(Path.GetTempPath(), $"Decod-Cue4Parse-{Guid.NewGuid():N}.usmap");
    File.WriteAllBytes(temporaryPath, converted);
    compatibility = "usmap_v4_to_v3_explicit_enum_values_omitted";
    return temporaryPath;
}

static byte[] ConvertUsmapV4ToV3(byte[] data)
{
    if (BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(0, 2)) != 0x30C4)
        throw new InvalidDataException("USMAP file has invalid magic.");
    if (BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(3, 4)) != 0)
        throw new NotSupportedException("USMAP v4 with version metadata cannot be converted.");
    if (data[7] != 0)
        throw new NotSupportedException("Compressed USMAP v4 files cannot be converted.");

    var payloadLength = data.Length - 16;
    var compressedSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(8, 4));
    var decompressedSize = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(12, 4));
    if (compressedSize != payloadLength || decompressedSize != payloadLength)
        throw new InvalidDataException("USMAP v4 payload size does not match its header.");

    var payload = data.AsSpan(16);
    var offset = 0;
    var nameCount = ReadUsmapInt32(payload, ref offset, "name count");
    if (nameCount < 0 || nameCount > (payload.Length - offset) / 2)
        throw new InvalidDataException("USMAP v4 name count is invalid.");

    for (var index = 0; index < nameCount; index++)
    {
        var nameLength = ReadUsmapUInt16(payload, ref offset, "name length");
        EnsureUsmapData(payload, offset, nameLength, "name");
        offset += nameLength;
    }

    var enumCount = ReadUsmapUInt32(payload, ref offset, "enum count");
    if (enumCount > (uint)((payload.Length - offset) / 6))
        throw new InvalidDataException("USMAP v4 enum count is invalid.");

    using var convertedPayload = new MemoryStream(payload.Length);
    convertedPayload.Write(payload[..offset]);
    for (var index = 0; index < enumCount; index++)
    {
        var enumHeaderOffset = offset;
        ReadUsmapInt32(payload, ref offset, "enum name index");
        var memberCount = ReadUsmapUInt16(payload, ref offset, "enum member count");
        convertedPayload.Write(payload.Slice(enumHeaderOffset, offset - enumHeaderOffset));

        if (memberCount > (payload.Length - offset) / 12)
            throw new InvalidDataException("USMAP v4 enum member count is invalid.");
        for (var member = 0; member < memberCount; member++)
        {
            EnsureUsmapData(payload, offset, 12, "enum member");
            convertedPayload.Write(payload.Slice(offset + 8, 4));
            offset += 12;
        }
    }
    convertedPayload.Write(payload[offset..]);

    var convertedData = new byte[16 + (int)convertedPayload.Length];
    data.AsSpan(0, 16).CopyTo(convertedData);
    convertedData[2] = 3;
    BinaryPrimitives.WriteUInt32LittleEndian(convertedData.AsSpan(8, 4), (uint)convertedPayload.Length);
    BinaryPrimitives.WriteUInt32LittleEndian(convertedData.AsSpan(12, 4), (uint)convertedPayload.Length);
    convertedPayload.ToArray().CopyTo(convertedData.AsSpan(16));
    return convertedData;
}

static int ReadUsmapInt32(ReadOnlySpan<byte> data, ref int offset, string field)
{
    EnsureUsmapData(data, offset, sizeof(int), field);
    var value = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(offset, sizeof(int)));
    offset += sizeof(int);
    return value;
}

static uint ReadUsmapUInt32(ReadOnlySpan<byte> data, ref int offset, string field)
{
    EnsureUsmapData(data, offset, sizeof(uint), field);
    var value = BinaryPrimitives.ReadUInt32LittleEndian(data.Slice(offset, sizeof(uint)));
    offset += sizeof(uint);
    return value;
}

static ushort ReadUsmapUInt16(ReadOnlySpan<byte> data, ref int offset, string field)
{
    EnsureUsmapData(data, offset, sizeof(ushort), field);
    var value = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, sizeof(ushort)));
    offset += sizeof(ushort);
    return value;
}

static void EnsureUsmapData(ReadOnlySpan<byte> data, int offset, int length, string field)
{
    if (offset < 0 || length < 0 || length > data.Length - offset)
        throw new InvalidDataException($"USMAP v4 is truncated while reading {field}.");
}

static string? FindMappingsPath(string paksDirectory)
{
    var configuredPath = Environment.GetEnvironmentVariable("DECOD_CUE4PARSE_USMAP");
    if (!string.IsNullOrWhiteSpace(configuredPath))
    {
        if (!File.Exists(configuredPath))
            throw new FileNotFoundException("Mappings file from DECOD_CUE4PARSE_USMAP was not found.", configuredPath);
        return Path.GetFullPath(configuredPath);
    }

    var gameRoot = Path.GetFullPath(Path.Combine(paksDirectory, "..", ".."));
    var candidateDirectories = new[]
    {
        gameRoot,
        Path.Combine(gameRoot, "Binaries", "Win64"),
        Path.Combine(gameRoot, "Binaries", "Win64", "ue4ss")
    };
    return candidateDirectories
        .Where(Directory.Exists)
        .SelectMany(directory => Directory.EnumerateFiles(directory, "*.usmap", SearchOption.TopDirectoryOnly))
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .OrderByDescending(File.GetLastWriteTimeUtc)
        .FirstOrDefault();
}

static bool HasUsefulExportDetails(UObject export)
{
    var type = export.ExportType;
    return type.Contains("Landscape", StringComparison.OrdinalIgnoreCase)
        || type.Contains("StaticMeshComponent", StringComparison.OrdinalIgnoreCase)
        || type.EndsWith("Actor", StringComparison.OrdinalIgnoreCase)
        || type.Equals("ActorPackInstance", StringComparison.OrdinalIgnoreCase)
        || type.Equals("SceneComponent", StringComparison.OrdinalIgnoreCase)
        || type.Equals("Texture2D", StringComparison.OrdinalIgnoreCase)
        || type.StartsWith("BP_", StringComparison.OrdinalIgnoreCase);
}

static ProbeOutcome ProbePackage(DefaultFileProvider provider, string probeAsset, string extractDirectory)
{
    var hasExtension = probeAsset.EndsWith(".uasset", StringComparison.OrdinalIgnoreCase)
        || probeAsset.EndsWith(".umap", StringComparison.OrdinalIgnoreCase);
    var packagePath = hasExtension ? probeAsset[..probeAsset.LastIndexOf('.')] : probeAsset;
    var assetFilePath = hasExtension ? probeAsset : probeAsset + ".uasset";
    byte[]? rawAsset = null;
    string? rawError = null;
    try
    {
        rawAsset = provider.SaveAsset(assetFilePath);
    }
    catch (Exception error)
    {
        rawError = error.Message;
    }

    var extractedFiles = new List<string>();
    var extractionErrors = new List<string>();
    if (!string.IsNullOrWhiteSpace(extractDirectory))
    {
        if (rawAsset is null)
        {
            extractionErrors.Add(rawError ?? "Could not read the package data.");
        }
        else
        {
            var extractionRoot = Path.GetFullPath(extractDirectory);
            var packageStem = assetFilePath[..assetFilePath.LastIndexOf('.')];
            var payloads = new List<(string Path, byte[] Data)> { (assetFilePath, rawAsset) };
            foreach (var extension in new[] { ".uexp", ".ubulk", ".uptnl" })
            {
                var companionPath = packageStem + extension;
                if (!provider.Files.ContainsKey(companionPath))
                    continue;
                try
                {
                    payloads.Add((companionPath, provider.SaveAsset(companionPath)));
                }
                catch (Exception error)
                {
                    extractionErrors.Add($"{companionPath}: {error.Message}");
                }
            }

            foreach (var payload in payloads)
            {
                var destination = Path.GetFullPath(Path.Combine(
                    extractionRoot,
                    payload.Path.Replace('/', Path.DirectorySeparatorChar)));
                if (!IsWithinDirectory(extractionRoot, destination))
                    throw new ArgumentException("Asset path escapes the requested extraction directory.");
                Directory.CreateDirectory(Path.GetDirectoryName(destination)!);
                File.WriteAllBytes(destination, payload.Data);
                extractedFiles.Add(destination);
            }
        }
    }

    string? parseError = null;
    object[]? exports = null;
    object[]? exportDetails = null;
    string[]? exportDetailsErrors = null;
    string? packageRuntimeType = null;
    try
    {
        var loadedPackage = provider.LoadPackage(packagePath);
        packageRuntimeType = loadedPackage.GetType().FullName;
        var packageExports = loadedPackage.GetExports().ToArray();
        exports = packageExports
            .Select(export => (object)new { name = export.Name, type = export.ExportType })
            .ToArray();
        var detailRecords = new List<object>();
        var detailErrors = new List<string>();
        foreach (var export in packageExports.Where(HasUsefulExportDetails))
        {
            try
            {
                if (export is Stalker2InstancedStaticMeshComponent
                    { InstanceDataDecodeError: not null } instancedComponent)
                {
                    detailErrors.Add($"{export.Name}: {instancedComponent.InstanceDataDecodeError}");
                }
                if (export is Stalker2BakedFoliageActor
                    { DeserializeError: not null } bakedFoliageActor)
                {
                    detailErrors.Add($"{export.Name}: {bakedFoliageActor.DeserializeError}");
                }
                detailRecords.Add(new
                {
                    name = export.Name,
                    type = export.ExportType,
                    parser_type = export.GetType().Name,
                    data = SerializeExport(export)
                });
            }
            catch (Newtonsoft.Json.JsonException error)
            {
                detailErrors.Add($"{export.Name}: {error.Message}");
            }
            catch (System.Text.Json.JsonException error)
            {
                detailErrors.Add($"{export.Name}: {error.Message}");
            }
        }
        exportDetails = detailRecords.ToArray();
        exportDetailsErrors = detailErrors.ToArray();
    }
    catch (Exception error)
    {
        parseError = error.Message;
    }

    var status = parseError is null
        ? exportDetailsErrors is { Length: > 0 } ? "partial" : "parsed"
        : rawAsset is not null ? "raw_only" : "error";
    var report = new
    {
        status,
        package = packagePath,
        raw_asset_bytes = rawAsset?.Length,
        raw_error = rawError,
        parse_status = parseError is null ? "success" : "error",
        parse_error = parseError,
        package_runtime_type = packageRuntimeType,
        exports,
        export_details = exportDetails,
        export_details_errors = exportDetailsErrors,
        extracted_files = extractedFiles,
        extraction_errors = extractionErrors
    };
    return new ProbeOutcome(status, packagePath, report);
}

static string SanitizeFileName(string packagePath)
{
    var fileName = Path.GetFileName(packagePath);
    var invalid = Path.GetInvalidFileNameChars();
    return string.Concat(fileName.Select(character => invalid.Contains(character) ? '_' : character));
}

static JsonElement SerializeExport(UObject export)
{
    var settings = new Newtonsoft.Json.JsonSerializerSettings
    {
        FloatFormatHandling = Newtonsoft.Json.FloatFormatHandling.String
    };
    using var document = JsonDocument.Parse(Newtonsoft.Json.JsonConvert.SerializeObject(export, settings));
    return document.RootElement.Clone();
}

static string? FindOodlePath(string paksDirectory)
{
    var configuredPath = Environment.GetEnvironmentVariable("DECOD_CUE4PARSE_OODLE_DLL");
    if (!string.IsNullOrWhiteSpace(configuredPath))
    {
        if (!File.Exists(configuredPath))
            throw new FileNotFoundException("Oodle DLL from DECOD_CUE4PARSE_OODLE_DLL was not found.", configuredPath);
        return Path.GetFullPath(configuredPath);
    }

    foreach (var start in new[]
    {
        new DirectoryInfo(paksDirectory),
        new DirectoryInfo(AppContext.BaseDirectory)
    })
    {
        for (var directory = start; directory is not null; directory = directory.Parent)
        {
            foreach (var candidate in new[]
            {
                Path.Combine(directory.FullName, "bin", OodleHelper.OODLE_DLL_NAME),
                Path.Combine(directory.FullName, "Binaries", "Win64", OodleHelper.OODLE_DLL_NAME)
            })
            {
                if (File.Exists(candidate))
                    return candidate;
            }
        }
    }

    return null;
}

static bool IsWithinDirectory(string root, string candidate)
{
    var relativePath = Path.GetRelativePath(root, candidate);
    return !Path.IsPathRooted(relativePath)
        && relativePath != ".."
        && !relativePath.StartsWith(".." + Path.DirectorySeparatorChar, StringComparison.Ordinal);
}

sealed record ProbeOutcome(string Status, string Package, object Report);
