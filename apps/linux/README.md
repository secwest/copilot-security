# Copilot Security for Linux

This directory contains the native Linux desktop application. It uses Avalonia on .NET 8 for the presentation layer and the same platform-neutral desktop and scanner-execution projects as the Windows WPF application. Security analysis, prompt orchestration, sealed-artifact validation, cancellation, history, and benchmark comparison therefore have one implementation across both platforms.

## Capabilities

- standard and deep scans of a repository, committed diff, working tree, or explicit path scope;
- model, reasoning-effort, authentication, cost, and optional AI-credit controls;
- repeatable knowledge-base and SARIF candidate inputs;
- optional expiring local secret-fingerprint baseline input;
- live stage/progress output, elapsed time, cancellation, and process-tree termination;
- validated findings with evidence, attack path, remediation, native report opening, and JSON/Markdown export;
- durable sealed scan history and report reload;
- strict corpus benchmark execution and baseline/candidate regression comparison; and
- executable, scanner, operating-system, architecture, and isolated-state diagnostics.

The GUI never invokes a shell to run a scan and never stores credentials. It accepts a completed result only after the shared artifact reader verifies document types, completion state, size bounds, required files, and the manifest hashes. Failed or canceled output remains diagnostic data, not a completed scan.

## State isolation

The scanner state root defaults to `~/.copilot-security` and can be changed in the application. The runtime remains under `$COPILOT_SECURITY_HOME/copilot-security-home`. Linux GUI history and benchmark output use `gui-linux-runs` and `gui-linux-benchmarks`, so they do not collide with the Windows GUI when the same state root is mounted in WSL.

Preferences contain paths and ordinary defaults only. They are stored at `$XDG_CONFIG_HOME/secwest/copilot-security/gui-linux/settings.json`, or `~/.config/secwest/copilot-security/gui-linux/settings.json` when `XDG_CONFIG_HOME` is absent or invalid. Path identity is case-sensitive and executable discovery requires a real file with at least one execute bit.

## Prerequisites

- a glibc-based x86-64 Linux distribution with X11, or WSL 2 with WSLg;
- the X11, fontconfig, ICE, SM, rendering, input, and OpenGL runtime libraries used by Avalonia;
- `bubblewrap`, which lets Copilot CLI provide its sandboxed shell on Linux (the scanner's built-in-file-tool path does not depend on shell availability);
- Node.js 22.13 or a supported newer release;
- an authenticated GitHub Copilot CLI; and
- for development builds, a built or installed `copilot-security.mjs` entry point outside the target repository. The CI archive includes the production scanner and its lockfile-resolved Linux dependencies beside the GUI.

On Ubuntu or WSL Ubuntu, install the native GUI libraries with:

```bash
sudo apt-get update
sudo apt-get install -y bubblewrap libx11-6 libice6 libsm6 libfontconfig1 libxrandr2 libxrender1 libxi6 libgl1
```

The self-contained package supplies .NET; developers building from source need the .NET 8 SDK.

## Build and test

From the repository root:

```bash
export AVALONIA_TELEMETRY_OPTOUT=1
export DOTNET_CLI_TELEMETRY_OPTOUT=1
dotnet restore apps/linux/CopilotSecurity.Gui.Tests/CopilotSecurity.Gui.Tests.csproj \
  --configfile apps/linux/NuGet.Config --locked-mode
dotnet build apps/linux/CopilotSecurity.Gui/CopilotSecurity.Gui.csproj \
  --configuration Release --no-restore
dotnet run --project apps/linux/CopilotSecurity.Gui.Tests/CopilotSecurity.Gui.Tests.csproj \
  --configuration Release --no-restore
```

The tests include a non-graphical startup contract and a headless Avalonia window that loads the tabs, bindings, data grids, commands, report view, and Linux-isolated state paths.

Publish a self-contained application:

```bash
dotnet restore apps/linux/CopilotSecurity.Gui/CopilotSecurity.Gui.csproj \
  --configfile apps/linux/NuGet.Config --runtime linux-x64 --locked-mode
dotnet publish apps/linux/CopilotSecurity.Gui/CopilotSecurity.Gui.csproj \
  --configuration Release --runtime linux-x64 --self-contained true \
  -p:DebugType=None --no-restore --output artifacts/linux-x64
./artifacts/linux-x64/CopilotSecurity --smoke-test
```

Under WSL, the Windows checkout is normally available below `/mnt/c`. The self-contained `linux-x64` output can be executed directly from that mounted path. `--ui-smoke-test` opens and closes the actual window after one second, which is useful for WSLg or `xvfb-run` validation.

## Install the packaged artifact

The CI package contains `app/`, the standalone scanner runtime, the launcher, desktop entry, icon, and installer. Extract it, then run:

```bash
sudo ./install.sh
copilot-security-gui
```

The installer checks for a complete executable payload before changing system paths. It installs the application below `/opt/copilot-security`, the launcher below `/usr/local/bin`, and freedesktop metadata below `/usr/share`.

## Failure and recovery behavior

- Missing or non-executable runtimes fail before process creation.
- Invalid repository/state/output overlap, repository-supplied scanner entry points, and unsafe link ancestry are rejected by the shared core.
- Cancellation terminates the process tree and leaves partial artifacts for diagnosis.
- Output capture is bounded; overflow fails the run and terminates its process tree.
- Malformed, incomplete, or hash-mismatched artifacts never appear as completed findings.
- Unexpected UI-dispatch exceptions terminate the desktop lifetime with a nonzero status rather than continuing with uncertain state.
- File-picker cancellation leaves the prior value unchanged, and exports copy only artifacts already accepted by the sealed-artifact reader.
