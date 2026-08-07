using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;
using Avalonia.Threading;

namespace Secwest.CopilotSecurity.Gui.Linux;

public sealed partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var window = new MainWindow();
            desktop.MainWindow = window;
            desktop.ShutdownMode = ShutdownMode.OnMainWindowClose;
            Dispatcher.UIThread.UnhandledException += (_, args) =>
            {
                Console.Error.WriteLine("Copilot Security GUI stopped after an unexpected UI error: " + args.Exception.Message);
                args.Handled = true;
                desktop.Shutdown(1);
            };
            if (desktop.Args?.Contains("--ui-smoke-test", StringComparer.Ordinal) == true)
            {
                desktop.ShutdownMode = ShutdownMode.OnExplicitShutdown;
                ConfigureUiSmokeShutdown(
                    window,
                    () => desktop.Shutdown(0),
                    () => Environment.Exit(0),
                    TimeSpan.FromSeconds(5));
            }
        }
        base.OnFrameworkInitializationCompleted();
    }

    public static void ConfigureUiSmokeShutdown(
        Window window,
        Action shutdown,
        Action forceExit,
        TimeSpan fallbackDelay)
    {
        ArgumentNullException.ThrowIfNull(window);
        ArgumentNullException.ThrowIfNull(shutdown);
        ArgumentNullException.ThrowIfNull(forceExit);
        if (fallbackDelay <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(fallbackDelay));
        }

        window.Opened += (_, _) =>
        {
            _ = Task.Run(async () =>
            {
                await Task.Delay(fallbackDelay).ConfigureAwait(false);
                forceExit();
            });
            Dispatcher.UIThread.Post(() =>
            {
                try
                {
                    window.Close();
                }
                finally
                {
                    shutdown();
                }
            });
        };
    }
}
