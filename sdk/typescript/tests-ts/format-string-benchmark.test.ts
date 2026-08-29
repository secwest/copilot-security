import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, test } from "bun:test";

const temporaryPaths: string[] = [];
const compiler = findCompiler();
const nativeTest = compiler === null ? test.skip : test;
const COMPILER_TIMEOUT_MS = 45_000;
const EXECUTABLE_TIMEOUT_MS = 30_000;
const NATIVE_TEST_TIMEOUT_MS = 180_000;

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

nativeTest(
  "format-string benchmark leaks the active capability while the literal-format control emits attacker input as data",
  async () => {
    expect(compiler).not.toBeNull();
    const root = await mkdtemp(
      join(tmpdir(), "copilot-security-format-string-benchmark-"),
    );
    temporaryPaths.push(root);
    const harness = join(root, "harness.c");
    await writeFile(
      harness,
      [
        "#include <stddef.h>",
        "#include <string.h>",
        "",
        "void audit_login_attempt(const char *remote_username,",
        "                         const char *active_session_secret,",
        "                         void (*emit_audit)(void *, const char *),",
        "                         void *context);",
        "",
        "static char emitted[256];",
        "",
        "static void capture(void *context, const char *message) {",
        "    (void)context;",
        "    strncpy(emitted, message, sizeof(emitted) - 1);",
        "    emitted[sizeof(emitted) - 1] = '\\0';",
        "}",
        "",
        "int main(void) {",
        '    static const char secret[] = "ADMIN_SESSION_CAPABILITY";',
        '    audit_login_attempt("alice", secret, capture, NULL);',
        '    if (strcmp(emitted, "alice") != 0) return 1;',
        "",
        "    memset(emitted, 0, sizeof(emitted));",
        '    audit_login_attempt("%s", secret, capture, NULL);',
        "#if EXPECT_SECRET_DISCLOSURE",
        "    return strcmp(emitted, secret) == 0 ? 0 : 2;",
        "#else",
        '    return strcmp(emitted, "%s") == 0 ? 0 : 3;',
        "#endif",
        "}",
        "",
      ].join("\n"),
    );

    const fixtures = resolve(
      process.cwd(),
      "..",
      "..",
      "benchmarks",
      "fixtures",
    );
    compileAndRun(
      compiler!,
      join(fixtures, "c-format-string-secret-disclosure", "src", "audit.c"),
      harness,
      join(root, executableName("vulnerable")),
      1,
    );
    compileAndRun(
      compiler!,
      join(fixtures, "c-safe-literal-format-audit", "src", "audit.c"),
      harness,
      join(root, executableName("safe")),
      0,
    );
  },
  { timeout: NATIVE_TEST_TIMEOUT_MS },
);

function findCompiler(): string | null {
  for (const candidate of ["cc", "gcc", "clang"]) {
    const result = spawnSync(candidate, ["--version"], {
      encoding: "utf8",
      windowsHide: true,
    });
    if (result.status === 0) return candidate;
  }
  return null;
}

function executableName(name: string): string {
  return process.platform === "win32" ? `${name}.exe` : name;
}

function compileAndRun(
  compilerPath: string,
  source: string,
  harness: string,
  executable: string,
  expectedSecretDisclosure: 0 | 1,
): void {
  const compilation = spawnSync(
    compilerPath,
    [
      "-std=c11",
      "-Wall",
      "-Wextra",
      "-Werror",
      `-DEXPECT_SECRET_DISCLOSURE=${expectedSecretDisclosure}`,
      source,
      harness,
      "-o",
      executable,
    ],
    {
      encoding: "utf8",
      timeout: COMPILER_TIMEOUT_MS,
      windowsHide: true,
    },
  );
  expect({
    status: compilation.status,
    stdout: compilation.stdout,
    stderr: compilation.stderr,
  }).toEqual({ status: 0, stdout: "", stderr: "" });

  const execution = spawnSync(executable, [], {
    encoding: "utf8",
    timeout: EXECUTABLE_TIMEOUT_MS,
    windowsHide: true,
  });
  expect({
    status: execution.status,
    signal: execution.signal,
    stdout: execution.stdout,
    stderr: execution.stderr,
  }).toEqual({
    status: 0,
    signal: null,
    stdout: "",
    stderr: "",
  });
}
