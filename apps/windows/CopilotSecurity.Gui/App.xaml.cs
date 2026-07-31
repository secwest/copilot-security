using System.IO;
using System.Windows;
using System.Windows.Threading;
using Secwest.CopilotSecurity.Core.Services;

namespace Secwest.CopilotSecurity.Gui;

public partial class App : System.Windows.Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        base.OnStartup(e);
    }

    private static void OnDispatcherUnhandledException(
        object sender,
        DispatcherUnhandledExceptionEventArgs e)
    {
        WriteCrashDiagnostic(e.Exception);
        System.Windows.MessageBox.Show(
            "The application encountered an unexpected interface error and will close safely.\n\n" + e.Exception.Message,
            "Copilot Security",
            MessageBoxButton.OK,
            MessageBoxImage.Error);
        e.Handled = true;
        Current.Shutdown(-1);
    }

    private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
    {
        WriteCrashDiagnostic(e.Exception);
        e.SetObserved();
    }

    private static void WriteCrashDiagnostic(Exception exception)
    {
        try
        {
            var directory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                ".copilot-security",
                "copilot-security-home",
                "gui");
            PathPolicy.RequireNoReparseAncestors(directory, "GUI diagnostic directory");
            Directory.CreateDirectory(directory);
            var path = Path.Combine(directory, "crash.log");
            var diagnostic = $"{DateTimeOffset.UtcNow:O}{Environment.NewLine}{exception}{Environment.NewLine}---{Environment.NewLine}";
            if (diagnostic.Length > 256 * 1024)
            {
                diagnostic = diagnostic[..(256 * 1024)];
            }
            if (File.Exists(path) &&
                (File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
            {
                return;
            }
            if (File.Exists(path) && new FileInfo(path).Length > 1024 * 1024)
            {
                File.WriteAllText(path, diagnostic);
            }
            else
            {
                File.AppendAllText(path, diagnostic);
            }
        }
        catch (Exception writeException) when (writeException is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // The original exception remains authoritative even if diagnostics cannot be persisted.
        }
    }
}
