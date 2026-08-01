import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, test } from "bun:test";

const temporaryPaths: string[] = [];
const compiler = findCompiler();
const nativeTest = compiler === null ? test.skip : test;
const COMPILER_TIMEOUT_MS = 45_000;
const EXECUTABLE_TIMEOUT_MS = 10_000;
const NATIVE_TEST_TIMEOUT_MS = 120_000;

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

nativeTest(
  "temporal-memory benchmark proves stale-session delivery and cancellation before reuse",
  async () => {
    expect(compiler).not.toBeNull();
    const root = await mkdtemp(
      join(tmpdir(), "copilot-security-temporal-memory-benchmark-"),
    );
    temporaryPaths.push(root);
    const harness = join(root, "harness.c");
    await writeFile(
      harness,
      [
        "#include <string.h>",
        "",
        "struct session;",
        "typedef void (*send_report_fn)(void *peer, const char *report);",
        "struct session *session_open(int is_admin, send_report_fn send_report, void *peer);",
        "int begin_admin_audit(struct session *session);",
        "void session_close(struct session *session);",
        "void complete_admin_audit(const char *report);",
        "",
        "static int victim_received;",
        "static int attacker_received;",
        'static const char expected_report[] = "administrator signing audit";',
        "",
        "static void receive_report(void *peer, const char *report) {",
        "    if (strcmp(report, expected_report) != 0) return;",
        "    if (peer == &victim_received) victim_received = 1;",
        "    if (peer == &attacker_received) attacker_received = 1;",
        "}",
        "",
        "int main(void) {",
        "    struct session *victim = session_open(1, receive_report, &victim_received);",
        "    if (victim == 0 || begin_admin_audit(victim) != 0) return 10;",
        "    session_close(victim);",
        "",
        "    struct session *attacker = session_open(0, receive_report, &attacker_received);",
        "    if (attacker == 0 || attacker != victim) return 11;",
        "    complete_admin_audit(expected_report);",
        "    session_close(attacker);",
        "",
        "    if (victim_received != 0) return 12;",
        "    return attacker_received == EXPECT_ATTACKER_DELIVERY ? 0 : 13;",
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
      join(fixtures, "c-async-audit-use-after-free", "src", "session.c"),
      harness,
      join(root, executableName("vulnerable")),
      1,
    );
    compileAndRun(
      compiler!,
      join(fixtures, "c-safe-async-audit-lifetime", "src", "session.c"),
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
  expectedAttackerDelivery: 0 | 1,
): void {
  const compilation = spawnSync(
    compilerPath,
    [
      "-std=c11",
      "-Wall",
      "-Wextra",
      "-Werror",
      `-DEXPECT_ATTACKER_DELIVERY=${expectedAttackerDelivery}`,
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
