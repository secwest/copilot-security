import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface GoExecRecord {
  path: string;
  line: number;
  categories: string[];
  frameworkModel?: {
    schemaVersion: string;
    id: string;
    language: string;
    scope: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

interface BenchmarkManifest {
  schemaVersion: string;
  thresholds: Record<string, number>;
  cases: Array<{
    id: string;
    expected: Array<{
      cwe?: string[];
      acceptableSeverities?: string[];
      requireValidation?: boolean;
      requireAttackPath?: boolean;
      requireCodeEvidence?: boolean;
    }>;
  }>;
}

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const caseIds = [
  "go-cross-file-shell-command-injection",
  "go-cross-file-safe-shell-command",
  "go-cross-file-manual-cmd-shell-injection",
  "go-cross-file-safe-manual-cmd-shell-command",
] as const;
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function models(inventory: string): GoExecRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as GoExecRecord)
    .filter(
      (record) => record.frameworkModel?.id === "go-os-exec-command-injection",
    );
}

async function repositoryInventory(
  files: Record<string, string>,
): Promise<GoExecRecord[]> {
  const repository = await mkdtemp(join(tmpdir(), "copilot-security-go-exec-"));
  temporaryPaths.push(repository);
  for (const [path, source] of Object.entries(files)) {
    const absolute = join(repository, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source);
  }
  return models(await buildResidualRiskInventory(repository));
}

async function fixtureInventory(id: (typeof caseIds)[number]): Promise<string> {
  return buildResidualRiskInventory(join(benchmarkRoot, "fixtures", id));
}

function handler(
  body: string,
  options: { execAlias?: string; execImport?: string; httpAlias?: string } = {},
): string {
  const execAlias = options.execAlias ?? "exec";
  const execImport = options.execImport ?? "os/exec";
  const httpAlias = options.httpAlias ?? "http";
  const execDeclaration =
    execAlias === "exec" ? `"${execImport}"` : `${execAlias} "${execImport}"`;
  const httpDeclaration =
    httpAlias === "http" ? '"net/http"' : `${httpAlias} "net/http"`;
  return `package render

import (
  ${execDeclaration}
  ${httpDeclaration}
)

func Render(w ${httpAlias}.ResponseWriter, r *${httpAlias}.Request) {
${body}
}
`;
}

describe("Go os/exec command-injection framework-model benchmark", () => {
  test("keeps the shell exploit and fixed-selection control under perfect gates", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "go-os-exec-command-injection-manifest.json"),
        "utf8",
      ),
    ) as BenchmarkManifest;
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }) => id)).toEqual([...caseIds]);
    expect(manifest.cases[0]?.expected[0]).toMatchObject({
      cwe: ["CWE-78"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.cases[2]?.expected[0]).toMatchObject({
      cwe: ["CWE-78"],
      acceptableSeverities: ["critical", "high"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[3]?.expected).toEqual([]);
  });

  test("preserves the exact handler-to-shell-construction-and-execution path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[0]));
    const safe = models(await fixtureInventory(caseIds[1]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "render.go",
      categories: [
        "framework-dataflow:go-os-exec-command-injection",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-process-shell-command-execution",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: { kind: "go-http-query-parameter", path: "handler.go" },
        sink: {
          kind: "go-process-shell-command-execution",
          path: "render.go",
          cweIds: ["CWE-78"],
        },
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-function-argument",
      "go-string-parameter",
      "go-string-assignment",
      "go-process-command-construction",
    ]);
    expect(safe).toEqual([]);
  });

  test("preserves the exact handler-to-manual-Args-mutation-and-execution path", async () => {
    const vulnerable = models(await fixtureInventory(caseIds[2]));
    const safe = models(await fixtureInventory(caseIds[3]));
    expect(vulnerable).toHaveLength(1);
    expect(vulnerable[0]).toMatchObject({
      path: "render.go",
      line: 14,
      categories: [
        "framework-dataflow:go-os-exec-command-injection",
        "modeled-source:go-http-query-parameter",
        "modeled-sink:go-process-shell-command-execution",
      ],
      frameworkModel: {
        schemaVersion: "1.2",
        language: "go",
        scope: "cross-file-wrapper",
        source: {
          kind: "go-http-query-parameter",
          path: "handler.go",
          line: 6,
        },
        sink: {
          kind: "go-process-shell-command-execution",
          path: "render.go",
          line: 14,
          cweIds: ["CWE-78"],
        },
      },
    });
    expect(
      vulnerable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toEqual([
      "go-function-argument",
      "go-string-parameter",
      "go-string-assignment",
      "go-process-args-field",
    ]);
    expect(safe).toEqual([]);
  });

  test("requires execution after attacker-controlled executable selection", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(`  program := r.URL.Query().Get("program")
  exec.Command(program)`),
      }),
    ).toEqual([]);
    for (const finisher of ["Run", "Start", "Output", "CombinedOutput"]) {
      const rows = await repositoryInventory({
        "render.go": handler(`  program := r.URL.Query().Get("program")
  exec.Command(program).${finisher}()`),
      });
      expect(rows, finisher).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-process-executable-selection",
      );
    }
  });

  test("tracks assigned command aliases and clears replacement", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(`  program := r.FormValue("program")
  command := exec.Command(program)
  alias := command
  alias.Run()`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": handler(`  program := r.FormValue("program")
  command := exec.Command(program)
  command = exec.Command("render")
  command.Run()`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "render.go": handler(`  program := r.FormValue("program")
  command := exec.Command(program)
  command.StdoutPipe()`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "render.go": `package render
import (
  "net/http"
  "os/exec"
)
func Other() {
  const hiddenShell = "sh"
  _ = hiddenShell
}
func Render(w http.ResponseWriter, r *http.Request) {
  exec.Command(hiddenShell, "-c", r.FormValue("command")).Run()
}`,
      }),
    ).toEqual([]);
  });

  test("closes manually constructed Cmd values only at process execution", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(`  program := r.FormValue("program")
  command := &exec.Cmd{Path: program}
  _ = command`),
      }),
    ).toEqual([]);
    const executable = await repositoryInventory({
      "render.go": handler(`  program := r.FormValue("program")
  command := &exec.Cmd{Path: program}
  command.Run()`),
    });
    expect(executable).toHaveLength(1);
    expect(executable[0]?.frameworkModel?.sink.kind).toBe(
      "go-process-executable-selection",
    );
    expect(
      executable[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-process-path-field");

    const shell = await repositoryInventory({
      "render.go": handler(`  command := r.FormValue("command")
  process := &exec.Cmd{
    Path: "sh",
    Args: []string{"display-name", "-c", command},
  }
  process.CombinedOutput()`),
    });
    expect(shell).toHaveLength(1);
    expect(shell[0]?.frameworkModel?.sink.kind).toBe(
      "go-process-shell-command-execution",
    );
    expect(
      shell[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-process-args-field");
  });

  test("tracks Path, Args, and exact Args element mutation without treating argv zero as executable", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(`  command := r.FormValue("command")
  var process exec.Cmd
  process.Path = "sh"
  process.Args = []string{"sh", "-c", "fixed"}
  process.Args[2] = command
  process.Run()`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": handler(`  value := r.FormValue("value")
  process := new(exec.Cmd)
  process.Path = "render"
  process.Args = []string{value, "--format", value}
  process.Start()`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "render.go": handler(`  command := r.FormValue("command")
  arguments := []string{"sh", "-c", "fixed"}
  arguments[2] = command
  process := &exec.Cmd{Path: "sh"}
  process.Args = arguments
  process.Output()`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": handler(`  command := r.FormValue("command")
  process := &exec.Cmd{Path: "sh", Args: []string{"sh", "-c", "fixed"}}
  alias := process
  process.Args[2] = command
  alias.Run()`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": handler(`  program := r.FormValue("program")
  process := exec.Cmd{Path: "render", Args: []string{"render"}}
  alias := process
  process.Path = program
  alias.Run()`),
      }),
    ).toEqual([]);
  });

  test("clears manual command state on replacement and keeps ordinary manual argv safe", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(`  command := r.FormValue("command")
  process := &exec.Cmd{Path: "sh", Args: []string{"sh", "-c", command}}
  process = exec.Command("render", "--format", "text")
  process.Run()`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "render.go": handler(`  value := r.FormValue("value")
  process := &exec.Cmd{Path: "render", Args: []string{"render", "--format", value}}
  process.Run()`),
      }),
    ).toEqual([]);
  });

  test("models immediate os and syscall process dispatch with exact argv roles", async () => {
    const osRows = await repositoryInventory({
      "render.go": `package render
import (
  "net/http"
  "os"
)
func Render(w http.ResponseWriter, r *http.Request) {
  command := r.FormValue("command")
  os.StartProcess("sh", []string{"sh", "-c", command}, nil)
}`,
    });
    expect(osRows).toHaveLength(1);
    expect(osRows[0]?.frameworkModel?.sink.kind).toBe(
      "go-process-shell-command-execution",
    );
    expect(
      osRows[0]?.frameworkModel?.propagators.map(({ kind }) => kind),
    ).toContain("go-process-direct-dispatch");

    for (const method of ["Exec", "ForkExec", "StartProcess"]) {
      const rows = await repositoryInventory({
        "render.go": `package render
import (
  "net/http"
  "syscall"
)
func Render(w http.ResponseWriter, r *http.Request) {
  command := r.FormValue("command")
  argv := []string{"sh", "-c", command}
  syscall.${method}("sh", argv, nil)
}`,
      });
      expect(rows, method).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "render.go": `package render
import (
  "net/http"
  "os"
)
func Render(w http.ResponseWriter, r *http.Request) {
  value := r.FormValue("value")
  os.StartProcess("render", []string{value, "--format", value}, nil)
}`,
      }),
    ).toEqual([]);
  });

  test("supports exact low-level aliases and one cross-file dispatcher wrapper", async () => {
    expect(
      await repositoryInventory({
        "render.go": `package render
import (
  "net/http"
  process "os"
)
func Render(w http.ResponseWriter, r *http.Request) {
  process.StartProcess(r.FormValue("program"), nil, nil)
}`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "handler.go": `package render
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) { Launch(r.FormValue("command")) }`,
        "launch.go": `package render
import "os"
func Launch(command string) { os.StartProcess("sh", []string{"sh", "-c", command}, nil) }`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": `package render
import (
  "net/http"
  "example.com/os"
)
func Render(w http.ResponseWriter, r *http.Request) {
  os.StartProcess(r.FormValue("program"), nil, nil)
}`,
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "render.go": `package render
import (
  "net/http"
  first "os"
  second "os"
)
func Render(w http.ResponseWriter, r *http.Request) {
  first.StartProcess(r.FormValue("program"), nil, nil)
  second.StartProcess(r.FormValue("program"), nil, nil)
}`,
      }),
    ).toEqual([]);
  });

  test("preserves CommandContext positions and keeps ordinary argument vectors safe", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(`  value := r.FormValue("value")
  exec.CommandContext(r.Context(), value).Run()`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": handler(`  value := r.FormValue("value")
  exec.CommandContext(r.Context(), "render", "--format", value).Run()`),
      }),
    ).toEqual([]);
  });

  test("models POSIX shell command strings but not post-command positional data", async () => {
    for (const shell of ["sh", "/bin/bash", "dash", "zsh", "fish"]) {
      expect(
        await repositoryInventory({
          "render.go": handler(`  command := r.FormValue("command")
  exec.Command(${JSON.stringify(shell)}, "-c", command).Run()`),
        }),
        shell,
      ).toHaveLength(1);
    }
    expect(
      await repositoryInventory({
        "render.go": handler(`  value := r.FormValue("value")
  exec.Command("sh", "-c", "printf '%s' \\"$1\\"", "render", value).Run()`),
      }),
    ).toEqual([]);
  });

  test("resolves immutable local and package shell constants", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(`  command := r.FormValue("command")
  shell := "/bin/sh"
  flag := "-c"
  exec.Command(shell, flag, command).Run()`),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": `package render
import (
  "net/http"
  "os/exec"
)
const shell = "sh"
func Render(w http.ResponseWriter, r *http.Request) {
  exec.Command(shell, "-c", r.FormValue("command")).Run()
}`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": handler(`  command := r.FormValue("command")
  shell := "sh"
  shell = "render"
  exec.Command(shell, "-c", command).Run()`),
      }),
    ).toEqual([]);
  });

  test("models Windows shell command strings", async () => {
    for (const [shell, flag] of [
      ["cmd.exe", "/c"],
      ["powershell.exe", "-Command"],
      ["pwsh", "-c"],
    ]) {
      const rows = await repositoryInventory({
        "render.go": handler(`  command := r.FormValue("command")
  exec.Command(${JSON.stringify(shell)}, ${JSON.stringify(flag)}, command).CombinedOutput()`),
      });
      expect(rows, shell).toHaveLength(1);
      expect(rows[0]?.frameworkModel?.sink.kind).toBe(
        "go-process-shell-command-execution",
      );
    }
    expect(
      await repositoryInventory({
        "render.go": handler(`  argument := r.FormValue("argument")
  exec.Command("C:\\\\tools\\\\render.cmd", argument).Run()`),
      }),
    ).toHaveLength(1);
  });

  test("models interpreter code and script selection", async () => {
    for (const [interpreter, flag] of [
      ["python3", "-c"],
      ["node", "--eval"],
      ["ruby", "-e"],
      ["perl", "-e"],
      ["php", "-r"],
    ]) {
      expect(
        await repositoryInventory({
          "render.go": handler(`  code := r.FormValue("code")
  exec.Command(${JSON.stringify(interpreter)}, ${JSON.stringify(flag)}, code).Run()`),
        }),
        interpreter,
      ).toHaveLength(1);
    }
    const script = await repositoryInventory({
      "render.go": handler(`  path := r.FormValue("path")
  exec.Command("python", path).Run()`),
    });
    expect(script[0]?.frameworkModel?.sink.kind).toBe(
      "go-process-interpreter-script-selection",
    );
  });

  test("models option-sensitive Git and rsync arguments with an exact terminator barrier", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(`  remote := r.FormValue("remote")
  exec.Command("git", "clone", remote, "/tmp/repository").Run()
  exec.Command("rsync", remote, "/tmp/output").Run()`),
      }),
    ).toHaveLength(2);
    expect(
      await repositoryInventory({
        "render.go": handler(`  remote := r.FormValue("remote")
  exec.Command("git", "clone", "--", remote, "/tmp/repository").Run()
  exec.Command("rsync", "--", remote, "/tmp/output").Run()`),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "render.go": handler(`  path := r.FormValue("path")
  exec.Command("git", "status", path).Run()`),
      }),
    ).toEqual([]);
  });

  test("models fixed-host SSH remote command grammar", async () => {
    const rows = await repositoryInventory({
      "render.go": handler(`  command := r.FormValue("command")
  exec.Command("ssh", "build@example.test", command).Run()`),
    });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.frameworkModel?.sink.kind).toBe(
      "go-process-indirect-argument-execution",
    );
  });

  test("accepts fixed server-owned command selection", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(`  format := r.FormValue("format")
  commands := map[string]string{"text": "render --text", "json": "render --json"}
  command := commands[format]
  exec.Command("sh", "-c", command).Run()`),
      }),
    ).toEqual([]);
  });

  test("supports exact aliases and execabs while rejecting lookalikes and ambiguous imports", async () => {
    expect(
      await repositoryInventory({
        "render.go": handler(
          `  command := r.FormValue("command")
  process.Command("sh", "-c", command).Run()`,
          { execAlias: "process" },
        ),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": handler(
          `  command := r.FormValue("command")
  execabs.Command("sh", "-c", command).Run()`,
          {
            execAlias: "execabs",
            execImport: "golang.org/x/sys/execabs",
          },
        ),
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "render.go": handler(
          `  command := r.FormValue("command")
  exec.Command("sh", "-c", command).Run()`,
          { execImport: "example.com/os/exec" },
        ),
      }),
    ).toEqual([]);
    expect(
      await repositoryInventory({
        "render.go": `package render
import (
  "net/http"
  first "os/exec"
  second "os/exec"
)
func Render(w http.ResponseWriter, r *http.Request) {
  first.Command("sh", "-c", r.FormValue("command")).Run()
  second.Command("sh", "-c", r.FormValue("command")).Run()
}`,
      }),
    ).toEqual([]);
  });

  test("follows one unique same-package wrapper and rejects ambiguity", async () => {
    expect(
      await repositoryInventory({
        "handler.go": `package render
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) { Run(r.FormValue("command")) }`,
        "run.go": `package render
import "os/exec"
func Run(command string) { exec.Command("sh", "-c", command).Run() }`,
      }),
    ).toHaveLength(1);
    expect(
      await repositoryInventory({
        "handler.go": `package render
import "net/http"
func Handler(w http.ResponseWriter, r *http.Request) { Run(r.FormValue("command")) }`,
        "run.go": `package render
import "os/exec"
func Run(command string) { exec.Command("sh", "-c", command).Run() }`,
        "duplicate.go": `package render
import "os/exec"
func Run(command string) { exec.Command("sh", "-c", command).Run() }`,
      }),
    ).toEqual([]);
  });

  test("retains candidate controls without treating them as universal sanitizers", async () => {
    const rows = await repositoryInventory({
      "render.go": `package render
import (
  "context"
  "net/http"
  "os/exec"
  "regexp"
  "strings"
)
func Render(w http.ResponseWriter, r *http.Request) {
  command := r.FormValue("command")
  if !regexp.MustCompile("^[A-Za-z ]+$").MatchString(command) { return }
  if strings.Contains(command, "..") { return }
  ctx, cancel := context.WithTimeout(r.Context(), 1)
  defer cancel()
  exec.LookPath("sh")
  exec.CommandContext(ctx, "sh", "-c", command).Run()
}`,
    });
    expect(rows).toHaveLength(1);
    expect(
      rows[0]?.frameworkModel?.candidateControls.map(({ kind }) => kind),
    ).toEqual([
      "process-input-allowlist",
      "process-argument-validation",
      "process-deadline",
      "executable-path-resolution",
    ]);
  });

  test("rejects comments and string examples", async () => {
    expect(
      await repositoryInventory({
        "render.go":
          handler(`  // exec.Command("sh", "-c", r.FormValue("command")).Run()
  example := "exec.Command(\\"sh\\", \\"-c\\", r.FormValue(\\"command\\")).Run()"
  _ = example`),
      }),
    ).toEqual([]);
  });

  test("teaches executable, shell, argument, closure, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row", "", "", "");
    expect(prompt).toContain("For go-os-exec-command-injection rows");
    expect(prompt).toContain("os/exec");
    expect(prompt).toContain("Run, Start, Output, or CombinedOutput");
    expect(prompt).toContain("manually populated Cmd");
    expect(prompt).toContain("Args[0]");
    expect(prompt).toContain("os.StartProcess");
    expect(prompt).toContain("ForkExec");
    expect(prompt).toContain("argument vector");
    expect(prompt).toContain("shell or interpreter");
    expect(prompt).toContain("option terminator");
    expect(prompt).toContain("concrete process capability");
  });
});
