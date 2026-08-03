using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Platform.Storage;
using Secwest.CopilotSecurity.Desktop;
using Secwest.CopilotSecurity.Desktop.ViewModels;

namespace Secwest.CopilotSecurity.Gui.Linux;

public sealed partial class MainWindow : Window
{
    public MainViewModel ViewModel => (MainViewModel)DataContext!;

    public MainWindow()
        : this(DesktopPlatformOptions.Linux())
    {
    }

    public MainWindow(DesktopPlatformOptions platform)
    {
        InitializeComponent();
        DataContext = new MainViewModel(platform);
    }

    protected override void OnClosed(EventArgs e)
    {
        ViewModel.Dispose();
        base.OnClosed(e);
    }

    private async void BrowseRepository_Click(object? sender, RoutedEventArgs e) =>
        ViewModel.RepositoryPath = await SelectFolderAsync("Select repository to scan", ViewModel.RepositoryPath)
            ?? ViewModel.RepositoryPath;

    private async void BrowseStateRoot_Click(object? sender, RoutedEventArgs e) =>
        ViewModel.StateRoot = await SelectFolderAsync("Select scanner state root", ViewModel.StateRoot)
            ?? ViewModel.StateRoot;

    private async void BrowseBenchmarkResults_Click(object? sender, RoutedEventArgs e) =>
        ViewModel.BenchmarkResultsDirectory = await SelectFolderAsync(
            "Select benchmark results directory",
            ViewModel.BenchmarkResultsDirectory) ?? ViewModel.BenchmarkResultsDirectory;

    private async void BrowseNode_Click(object? sender, RoutedEventArgs e) =>
        ViewModel.NodePath = await SelectFileAsync("Select Node.js executable", ViewModel.NodePath)
            ?? ViewModel.NodePath;

    private async void BrowseCopilot_Click(object? sender, RoutedEventArgs e) =>
        ViewModel.CopilotPath = await SelectFileAsync("Select Copilot CLI executable", ViewModel.CopilotPath)
            ?? ViewModel.CopilotPath;

    private async void BrowseScanner_Click(object? sender, RoutedEventArgs e) =>
        ViewModel.ScannerEntryPoint = await SelectFileAsync("Select scanner entry point", ViewModel.ScannerEntryPoint)
            ?? ViewModel.ScannerEntryPoint;

    private async void BrowseBenchmarkManifest_Click(object? sender, RoutedEventArgs e) =>
        ViewModel.BenchmarkManifest = await SelectFileAsync("Select benchmark manifest", ViewModel.BenchmarkManifest, "*.json")
            ?? ViewModel.BenchmarkManifest;

    private async void BrowseBaselineReport_Click(object? sender, RoutedEventArgs e) =>
        ViewModel.BaselineBenchmarkReport = await SelectFileAsync(
            "Select baseline benchmark report",
            ViewModel.BaselineBenchmarkReport,
            "*.json") ?? ViewModel.BaselineBenchmarkReport;

    private async void BrowseCandidateReport_Click(object? sender, RoutedEventArgs e) =>
        ViewModel.CandidateBenchmarkReport = await SelectFileAsync(
            "Select candidate benchmark report",
            ViewModel.CandidateBenchmarkReport,
            "*.json") ?? ViewModel.CandidateBenchmarkReport;

    private async void ExportFindings_Click(object? sender, RoutedEventArgs e) =>
        await ExportValidatedArtifactAsync(ViewModel.CurrentArtifacts?.FindingsPath, "findings.json", "JSON", "*.json");

    private async void ExportReport_Click(object? sender, RoutedEventArgs e) =>
        await ExportValidatedArtifactAsync(ViewModel.CurrentArtifacts?.ReportPath, "security-report.md", "Markdown", "*.md");

    private async Task<string?> SelectFolderAsync(string title, string suggestedPath)
    {
        var options = new FolderPickerOpenOptions { Title = title, AllowMultiple = false };
        options.SuggestedStartLocation = await ResolveFolderAsync(suggestedPath);
        var selected = await StorageProvider.OpenFolderPickerAsync(options);
        return selected.Count == 1 ? selected[0].TryGetLocalPath() : null;
    }

    private async Task<string?> SelectFileAsync(string title, string suggestedPath, string pattern = "*")
    {
        var options = new FilePickerOpenOptions
        {
            Title = title,
            AllowMultiple = false,
            FileTypeFilter = [new FilePickerFileType("Files") { Patterns = [pattern] }],
            SuggestedStartLocation = await ResolveFolderAsync(Path.GetDirectoryName(suggestedPath)),
        };
        var selected = await StorageProvider.OpenFilePickerAsync(options);
        return selected.Count == 1 ? selected[0].TryGetLocalPath() : null;
    }

    private async Task<IStorageFolder?> ResolveFolderAsync(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return null;
        var candidate = Directory.Exists(path) ? path : Path.GetDirectoryName(path);
        if (string.IsNullOrWhiteSpace(candidate) || !Directory.Exists(candidate)) return null;
        return await StorageProvider.TryGetFolderFromPathAsync(Path.GetFullPath(candidate));
    }

    private async Task ExportValidatedArtifactAsync(
        string? sourcePath,
        string suggestedName,
        string typeName,
        string pattern)
    {
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath)) return;
        var destination = await StorageProvider.SaveFilePickerAsync(new FilePickerSaveOptions
        {
            Title = "Export validated " + typeName.ToLowerInvariant(),
            SuggestedFileName = suggestedName,
            DefaultExtension = Path.GetExtension(suggestedName).TrimStart('.'),
            FileTypeChoices = [new FilePickerFileType(typeName) { Patterns = [pattern] }],
        });
        if (destination is null) return;

        await using var input = new FileStream(
            sourcePath,
            FileMode.Open,
            FileAccess.Read,
            FileShare.Read,
            64 * 1024,
            FileOptions.Asynchronous | FileOptions.SequentialScan);
        await using var output = await destination.OpenWriteAsync();
        output.SetLength(0);
        await input.CopyToAsync(output);
        await output.FlushAsync();
    }
}
