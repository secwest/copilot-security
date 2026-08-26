import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, test } from "bun:test";

const temporaryPaths: string[] = [];
const compiler = findCompiler();
const nativeTest = compiler === null ? test.skip : test;
const COMPILER_TIMEOUT_MS = 45_000;
// The witnesses normally finish in under two seconds, but a full parallel
// native suite can briefly starve a just-launched Windows process. Keep the
// subprocess bound well below the enclosing test bound without turning host
// scheduling pressure into a false regression.
const EXECUTABLE_TIMEOUT_MS = 30_000;
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
    const vulnerableHarness = join(root, "vulnerable-harness.c");
    await writeFile(
      vulnerableHarness,
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
    const safeHarness = join(root, "safe-harness.c");
    await writeFile(
      safeHarness,
      [
        "#include <stdint.h>",
        "#include <string.h>",
        "",
        "typedef void (*send_report_fn)(void *peer, const char *report);",
        "typedef uint64_t session_handle;",
        "session_handle session_open(int is_admin, send_report_fn send_report, void *peer);",
        "int begin_admin_audit(session_handle handle);",
        "void session_close(session_handle handle);",
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
        "    session_handle victim = session_open(1, receive_report, &victim_received);",
        "    if (victim == 0 || begin_admin_audit(victim) != 0) return 10;",
        "    session_close(victim);",
        "",
        "    session_handle attacker = session_open(0, receive_report, &attacker_received);",
        "    if (attacker == 0 || attacker == victim) return 11;",
        "    if (begin_admin_audit(victim) == 0) return 12;",
        "    complete_admin_audit(expected_report);",
        "    session_close(attacker);",
        "",
        "    if (victim_received != 0) return 13;",
        "    return attacker_received == EXPECT_ATTACKER_DELIVERY ? 0 : 14;",
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
      vulnerableHarness,
      join(root, executableName("vulnerable")),
      1,
    );
    compileAndRun(
      compiler!,
      join(fixtures, "c-safe-async-audit-lifetime", "src", "session.c"),
      safeHarness,
      join(root, executableName("safe")),
      0,
    );
  },
  { timeout: NATIVE_TEST_TIMEOUT_MS },
);

nativeTest(
  "safe completion retains the claimed session across a reentrant close",
  async () => {
    expect(compiler).not.toBeNull();
    const root = await mkdtemp(
      join(tmpdir(), "copilot-security-retained-lifetime-benchmark-"),
    );
    temporaryPaths.push(root);
    const harness = join(root, "reentrant-harness.c");
    await writeFile(
      harness,
      [
        "#include <stdint.h>",
        "",
        "typedef void (*send_report_fn)(void *peer, const char *report);",
        "typedef uint64_t session_handle;",
        "session_handle session_open(int is_admin, send_report_fn send_report, void *peer);",
        "int begin_admin_audit(session_handle handle);",
        "void session_close(session_handle handle);",
        "void complete_admin_audit(const char *report);",
        "",
        "static session_handle victim;",
        "static int replacement_succeeded_during_callback;",
        "",
        "static void receive_report(void *peer, const char *report) {",
        "    (void)peer;",
        "    (void)report;",
        "    session_close(victim);",
        "    session_handle replacement = session_open(0, receive_report, 0);",
        "    if (replacement != 0) {",
        "        replacement_succeeded_during_callback = 1;",
        "        session_close(replacement);",
        "    }",
        "}",
        "",
        "int main(void) {",
        "    victim = session_open(1, receive_report, 0);",
        "    if (victim == 0 || begin_admin_audit(victim) != 0) return 20;",
        '    complete_admin_audit("administrator signing audit");',
        "    if (replacement_succeeded_during_callback != 0) return 21;",
        "",
        "    session_handle replacement = session_open(0, receive_report, 0);",
        "    if (replacement == 0 || replacement == victim) return 22;",
        "    session_close(replacement);",
        "    return 0;",
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
      join(fixtures, "c-safe-async-audit-lifetime", "src", "session.c"),
      harness,
      join(root, executableName("retained-lifetime")),
      0,
    );
  },
  { timeout: NATIVE_TEST_TIMEOUT_MS },
);

nativeTest(
  "safe handles reject cross-generation use after slot reuse",
  async () => {
    expect(compiler).not.toBeNull();
    const root = await mkdtemp(
      join(tmpdir(), "copilot-security-generation-handle-benchmark-"),
    );
    temporaryPaths.push(root);
    const harness = join(root, "generation-harness.c");
    await writeFile(
      harness,
      [
        "#include <stdint.h>",
        "",
        "typedef void (*send_report_fn)(void *peer, const char *report);",
        "typedef uint64_t session_handle;",
        "session_handle session_open(int is_admin, send_report_fn send_report, void *peer);",
        "int begin_admin_audit(session_handle handle);",
        "void session_close(session_handle handle);",
        "void complete_admin_audit(const char *report);",
        "",
        "static void receive_report(void *peer, const char *report) {",
        "    (void)peer;",
        "    (void)report;",
        "}",
        "",
        "int main(void) {",
        "    session_handle stale = session_open(0, receive_report, 0);",
        "    if (stale == 0) return 30;",
        "    session_close(stale);",
        "",
        "    session_handle administrator = session_open(1, receive_report, 0);",
        "    if (administrator == 0 || administrator == stale) return 31;",
        "    if (begin_admin_audit(stale) == 0) return 32;",
        "    session_close(stale);",
        "    if (begin_admin_audit(administrator) != 0) return 33;",
        "    session_close(administrator);",
        '    complete_admin_audit("administrator signing audit");',
        "    return 0;",
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
      join(fixtures, "c-safe-async-audit-lifetime", "src", "session.c"),
      harness,
      join(root, executableName("generation-handle")),
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
