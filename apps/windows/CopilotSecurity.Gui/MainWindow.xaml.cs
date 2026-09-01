using System.ComponentModel;
using System.IO;
using System.Windows;
using Microsoft.Win32;
using Secwest.CopilotSecurity.Desktop;
using Secwest.CopilotSecurity.Desktop.ViewModels;
using Forms = System.Windows.Forms;

namespace Secwest.CopilotSecurity.Gui;

public partial class MainWindow : Window
{
    private bool shutdownStarted;
    private bool shutdownComplete;
    private MainViewModel ViewModel => (MainViewModel)DataContext;

    public MainWindow()
    {
        InitializeComponent();
        DataContext = new MainViewModel(DesktopPlatformOptions.Windows());
    }

    protected override async void OnClosing(CancelEventArgs e)
    {
        if (shutdownComplete)
        {
            base.OnClosing(e);
            return;
        }
        e.Cancel = true;
        base.OnClosing(e);
        if (shutdownStarted)
        {
            return;
        }
        shutdownStarted = true;
        await ViewModel.DisposeAsync();
        shutdownComplete = true;
        Close();
    }

    private void BrowseRepository_Click(object sender, RoutedEventArgs e)
    {
        var value = SelectFolder(ViewModel.RepositoryPath, "Select repository to scan");
        if (value is not null)
        {
            ViewModel.RepositoryPath = value;
        }
    }

    private void BrowseStateRoot_Click(object sender, RoutedEventArgs e)
    {
        var value = SelectFolder(ViewModel.StateRoot, "Select scanner state root");
        if (value is not null)
        {
            ViewModel.StateRoot = value;
        }
    }

    private void BrowseBenchmarkResults_Click(object sender, RoutedEventArgs e)
    {
        var value = SelectFolder(ViewModel.BenchmarkResultsDirectory, "Select benchmark results directory");
        if (value is not null)
        {
            ViewModel.BenchmarkResultsDirectory = value;
        }
    }

    private void BrowseBenchmarkManifest_Click(object sender, RoutedEventArgs e) =>
        AssignFile("JSON files (*.json)|*.json|All files (*.*)|*.*", path => ViewModel.BenchmarkManifest = path);

    private void BrowseBaselineReport_Click(object sender, RoutedEventArgs e) =>
        AssignFile("Benchmark report (benchmark-report.json)|benchmark-report.json|JSON files (*.json)|*.json", path => ViewModel.BaselineBenchmarkReport = path);

    private void BrowseCandidateReport_Click(object sender, RoutedEventArgs e) =>
        AssignFile("Benchmark report (benchmark-report.json)|benchmark-report.json|JSON files (*.json)|*.json", path => ViewModel.CandidateBenchmarkReport = path);

    private void BrowseNode_Click(object sender, RoutedEventArgs e) =>
        AssignFile("Executables (*.exe)|*.exe|All files (*.*)|*.*", path => ViewModel.NodePath = path);

    private void BrowseScanner_Click(object sender, RoutedEventArgs e) =>
        AssignFile("JavaScript modules (*.mjs)|*.mjs|All files (*.*)|*.*", path => ViewModel.ScannerEntryPoint = path);

    private void BrowseCopilot_Click(object sender, RoutedEventArgs e) =>
        AssignFile("Executables and commands (*.exe;*.cmd)|*.exe;*.cmd|All files (*.*)|*.*", path => ViewModel.CopilotPath = path);

    private static string? SelectFolder(string initialDirectory, string description)
    {
        using var dialog = new Forms.FolderBrowserDialog
        {
            Description = description,
            UseDescriptionForTitle = true,
            ShowNewFolderButton = true,
            InitialDirectory = Directory.Exists(initialDirectory) ? initialDirectory : string.Empty,
        };
        return dialog.ShowDialog() == Forms.DialogResult.OK ? dialog.SelectedPath : null;
    }

    private static void AssignFile(string filter, Action<string> assign)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            CheckFileExists = true,
            Multiselect = false,
            Filter = filter,
        };
        if (dialog.ShowDialog() == true)
        {
            assign(dialog.FileName);
        }
    }
}
