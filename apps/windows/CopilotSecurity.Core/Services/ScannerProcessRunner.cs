using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Secwest.CopilotSecurity.Core.Models;

namespace Secwest.CopilotSecurity.Core.Services;

public sealed partial class ScannerProcessRunner
{
    private const int MaximumStandardOutputCharacters = 64 * 1024 * 1024;
    private const int MaximumStandardErrorCharacters = 8 * 1024 * 1024;

    public async Task<ScannerProcessResult> RunAsync(
        ScannerInvocation invocation,
        IProgress<ScannerProgress>? progress,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(invocation);
        var startInfo = new ProcessStartInfo
        {
            FileName = invocation.FileName,
            WorkingDirectory = invocation.WorkingDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
        };
        foreach (var argument in invocation.Arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }
        foreach (var pair in invocation.Environment)
        {
            startInfo.Environment[pair.Key] = pair.Value;
        }

        using var process = new Process { StartInfo = startInfo, EnableRaisingEvents = true };
        var stopwatch = Stopwatch.StartNew();
        try
        {
            if (!process.Start())
            {
                return Failure(stopwatch.Elapsed, "Scanner process did not start.");
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return Failure(stopwatch.Elapsed, "Scanner process could not be started: " + exception.Message);
        }

        var standardOutput = new StringBuilder();
        var standardError = new StringBuilder();
        var outputTask = ReadBoundedAsync(
            process.StandardOutput,
            standardOutput,
            MaximumStandardOutputCharacters,
            null,
            CancellationToken.None);
        var errorTask = ReadBoundedAsync(
            process.StandardError,
            standardError,
            MaximumStandardErrorCharacters,
            line => progress?.Report(ParseProgress(line)),
            CancellationToken.None);
        var streamTask = Task.WhenAll(outputTask, errorTask);
        var exitTask = process.WaitForExitAsync(cancellationToken);

        try
        {
            var first = await Task.WhenAny(exitTask, streamTask).ConfigureAwait(false);
            await first.ConfigureAwait(false);
            await exitTask.ConfigureAwait(false);
            await streamTask.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            KillProcessTree(process);
            await DrainAfterTerminationAsync(outputTask, errorTask).ConfigureAwait(false);
            return new ScannerProcessResult(
                ScanRunState.Canceled,
                process.HasExited ? process.ExitCode : null,
                stopwatch.Elapsed,
                standardOutput.ToString(),
                standardError.ToString(),
                "Scan canceled. Partial scanner artifacts, if any, remain in the selected output directory.");
        }
        catch (InvalidDataException exception)
        {
            KillProcessTree(process);
            await DrainAfterTerminationAsync(outputTask, errorTask).ConfigureAwait(false);
            return Failure(
                stopwatch.Elapsed,
                exception.Message,
                standardOutput.ToString(),
                standardError.ToString(),
                process.HasExited ? process.ExitCode : null);
        }
        catch (IOException exception)
        {
            KillProcessTree(process);
            await DrainAfterTerminationAsync(outputTask, errorTask).ConfigureAwait(false);
            return Failure(
                stopwatch.Elapsed,
                "Scanner output could not be read safely: " + exception.Message,
                standardOutput.ToString(),
                standardError.ToString(),
                process.HasExited ? process.ExitCode : null);
        }

        var state = process.ExitCode == 0 ? ScanRunState.Completed : ScanRunState.Failed;
        return new ScannerProcessResult(
            state,
            process.ExitCode,
            stopwatch.Elapsed,
            standardOutput.ToString(),
            standardError.ToString(),
            process.ExitCode == 0 ? null : SafeFailureSummary(standardError.ToString()));
    }

    private static async Task ReadBoundedAsync(
        StreamReader reader,
        StringBuilder destination,
        int maximumCharacters,
        Action<string>? onLine,
        CancellationToken cancellationToken)
    {
        while (await reader.ReadLineAsync(cancellationToken).ConfigureAwait(false) is { } line)
        {
            if (destination.Length + line.Length + Environment.NewLine.Length > maximumCharacters)
            {
                throw new InvalidDataException(
                    $"Scanner output exceeded the bounded {maximumCharacters}-character capture limit.");
            }
            destination.AppendLine(line);
            try
            {
                onLine?.Invoke(line);
            }
            catch (Exception)
            {
                // Progress observers cannot change scanner execution or artifact validity.
            }
        }
    }

    private static async Task DrainAfterTerminationAsync(params Task[] tasks)
    {
        try
        {
            await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is TimeoutException or IOException or InvalidDataException)
        {
            // The process has already been terminated; bounded partial output is retained.
        }
    }

    private static void KillProcessTree(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(5_000);
            }
        }
        catch (Exception exception) when (exception is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            // Best-effort termination; the caller still reports cancellation/failure.
        }
    }

    private static ScannerProcessResult Failure(
        TimeSpan elapsed,
        string message,
        string standardOutput = "",
        string standardError = "",
        int? exitCode = null) =>
        new(
            ScanRunState.Failed,
            exitCode,
            elapsed,
            standardOutput,
            standardError,
            message);

    private static ScannerProgress ParseProgress(string line)
    {
        var match = ProgressLine().Match(line);
        return match.Success
            ? new ScannerProgress(
                DateTimeOffset.Now,
                match.Groups["stage"].Value,
                match.Groups["message"].Value,
                line)
            : new ScannerProgress(DateTimeOffset.Now, "scanner", line, line);
    }

    private static string SafeFailureSummary(string standardError)
    {
        var lines = standardError
            .Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .TakeLast(8)
            .ToArray();
        return lines.Length == 0
            ? "Scanner exited without a diagnostic."
            : string.Join(Environment.NewLine, lines);
    }

    [GeneratedRegex(@"^\[(?<stage>\d\d:\d\d)\]\s+(?<message>.+)$", RegexOptions.CultureInvariant)]
    private static partial Regex ProgressLine();
}
