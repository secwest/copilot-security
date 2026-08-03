# Shared desktop application layer

`CopilotSecurity.Desktop` contains the platform-neutral behavior used by the native desktop applications:

- scanner command construction and process-tree cancellation through `CopilotSecurity.Core`;
- progress, findings, report, history, benchmark, comparison, diagnostics, and durable-settings state;
- platform-specific executable discovery and path identity through an immutable `DesktopPlatformOptions` profile.

The project has no WPF, Windows Forms, Avalonia, or other presentation dependency. Windows retains its established preferences and `gui-runs`/`gui-benchmarks` paths. Linux uses XDG-compatible preferences and separate `gui-linux-runs`/`gui-linux-benchmarks` paths. Both use `COPILOT_SECURITY_HOME` and the scanner-owned `copilot-security-home` runtime directory.

Run its regression tests from the repository root:

```powershell
dotnet run `
  --project apps/desktop/CopilotSecurity.Desktop.Tests/CopilotSecurity.Desktop.Tests.csproj `
  --configuration Release
```
