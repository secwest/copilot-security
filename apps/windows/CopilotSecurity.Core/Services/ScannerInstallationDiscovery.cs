namespace Secwest.CopilotSecurity.Core.Services;

public static class ScannerInstallationDiscovery
{
    public static string? FindInstalledFile(
        string applicationBaseDirectory,
        params string[] segments)
    {
        if (segments.Length == 0 || segments.Any(segment =>
            string.IsNullOrWhiteSpace(segment) ||
            Path.IsPathRooted(segment) ||
            segment is "." or ".." ||
            segment.IndexOfAny([Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar]) >= 0))
        {
            throw new ArgumentException(
                "Installed-file discovery requires nonempty literal path segments.",
                nameof(segments));
        }

        var canonicalBase = PathPolicy.ExistingDirectory(
            applicationBaseDirectory,
            "Application base directory");
        PathPolicy.RequireNoReparseAncestors(canonicalBase, "Application base directory");
        var directory = new DirectoryInfo(canonicalBase);
        for (var depth = 0; directory is not null && depth < 10; depth++, directory = directory.Parent)
        {
            var candidate = Path.Combine([directory.FullName, .. segments]);
            if (!File.Exists(candidate))
            {
                continue;
            }

            PathPolicy.RequireNoReparseAncestors(candidate, "Installed file");
            return Path.GetFullPath(candidate);
        }

        return null;
    }
}
