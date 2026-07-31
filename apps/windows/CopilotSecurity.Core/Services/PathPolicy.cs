namespace Secwest.CopilotSecurity.Core.Services;

public static class PathPolicy
{
    private static readonly StringComparison PathComparison =
        OperatingSystem.IsWindows()
            ? StringComparison.OrdinalIgnoreCase
            : StringComparison.Ordinal;

    public static string ExistingDirectory(string path, string label)
    {
        var fullPath = Canonical(path, label);
        if (!Directory.Exists(fullPath))
        {
            throw new ArgumentException($"{label} does not exist or is not a directory.", label);
        }

        return fullPath;
    }

    public static string ExistingFile(string path, string label)
    {
        var fullPath = Canonical(path, label);
        if (!File.Exists(fullPath))
        {
            throw new ArgumentException($"{label} does not exist or is not a file.", label);
        }

        return fullPath;
    }

    public static string Canonical(string path, string label)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException($"{label} cannot be empty.", label);
        }

        if (path.IndexOf('\0') >= 0)
        {
            throw new ArgumentException($"{label} contains an invalid character.", label);
        }

        return Path.GetFullPath(path.Trim());
    }

    public static bool IsEqualOrNested(string candidate, string parent)
    {
        var fullCandidate = EnsureTrailingSeparator(Path.GetFullPath(candidate));
        var fullParent = EnsureTrailingSeparator(Path.GetFullPath(parent));
        return fullCandidate.StartsWith(fullParent, PathComparison);
    }

    public static void RequireDisjoint(string left, string right, string message)
    {
        if (IsEqualOrNested(left, right) || IsEqualOrNested(right, left))
        {
            throw new ArgumentException(message);
        }
    }

    public static void RequireScannerOwnedState(string stateRoot)
    {
        var canonical = Canonical(stateRoot, "Scanner state root");
        RequireNoReparseAncestors(canonical, "Scanner state root");
        foreach (var segment in canonical.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
        {
            if (segment.Equals("copilot-security-home", StringComparison.OrdinalIgnoreCase))
            {
                throw new ArgumentException(
                    "Scanner state root must be the parent of copilot-security-home, not the runtime directory itself.",
                    nameof(stateRoot));
            }
        }
    }

    public static void RequireNoReparseAncestors(string path, string label)
    {
        var canonical = Canonical(path, label);
        var root = Path.GetPathRoot(canonical)
            ?? throw new ArgumentException($"{label} has no filesystem root.", label);
        var current = root;
        var remainder = canonical[root.Length..];
        foreach (var segment in remainder.Split(
            [Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar],
            StringSplitOptions.RemoveEmptyEntries))
        {
            current = Path.Combine(current, segment);
            if (!File.Exists(current) && !Directory.Exists(current))
            {
                continue;
            }
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
            {
                throw new ArgumentException($"{label} must not traverse a reparse point.", label);
            }
        }
    }

    private static string EnsureTrailingSeparator(string path) =>
        path.EndsWith(Path.DirectorySeparatorChar) ? path : path + Path.DirectorySeparatorChar;
}
