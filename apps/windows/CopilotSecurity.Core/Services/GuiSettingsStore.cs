using System.Text.Json;
using System.Text.Json.Serialization;
using Secwest.CopilotSecurity.Core.Models;

namespace Secwest.CopilotSecurity.Core.Services;

public sealed class GuiSettingsStore
{
    private const long MaximumSettingsBytes = 1024 * 1024;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
        AllowTrailingCommas = false,
        ReadCommentHandling = JsonCommentHandling.Disallow,
    };

    public GuiSettings? Load(string settingsPath)
    {
        var path = PathPolicy.Canonical(settingsPath, "GUI settings path");
        PathPolicy.RequireNoReparseAncestors(path, "GUI settings path");
        if (!File.Exists(path))
        {
            return null;
        }
        var information = new FileInfo(path);
        if ((information.Attributes & FileAttributes.ReparsePoint) != 0)
        {
            throw new InvalidDataException("GUI settings file must not be a reparse point.");
        }
        if (information.Length > MaximumSettingsBytes)
        {
            throw new InvalidDataException("GUI settings file exceeds the 1 MiB limit.");
        }
        return JsonSerializer.Deserialize<GuiSettings>(File.ReadAllText(path), JsonOptions)
            ?? throw new InvalidDataException("GUI settings file is empty.");
    }

    public void Save(string settingsPath, GuiSettings settings)
    {
        ArgumentNullException.ThrowIfNull(settings);
        var path = PathPolicy.Canonical(settingsPath, "GUI settings path");
        PathPolicy.RequireNoReparseAncestors(path, "GUI settings path");
        var directory = Path.GetDirectoryName(path)
            ?? throw new ArgumentException("GUI settings path has no parent directory.", nameof(settingsPath));
        Directory.CreateDirectory(directory);
        var temporary = Path.Combine(directory, ".settings-" + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(settings, JsonOptions);
            if (bytes.Length > MaximumSettingsBytes)
            {
                throw new InvalidDataException("GUI settings exceed the 1 MiB limit.");
            }
            using (var stream = new FileStream(
                temporary,
                FileMode.CreateNew,
                FileAccess.Write,
                FileShare.None,
                16 * 1024,
                FileOptions.WriteThrough))
            {
                stream.Write(bytes);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, path, overwrite: true);
        }
        finally
        {
            try
            {
                File.Delete(temporary);
            }
            catch (IOException)
            {
                // The durable destination is already authoritative.
            }
        }
    }
}
