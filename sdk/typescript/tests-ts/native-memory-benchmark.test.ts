import { spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, expect, test } from "bun:test";

const temporaryPaths: string[] = [];
const compiler = findCompiler();
const nativeTest = compiler === null ? test.skip : test;

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

nativeTest(
  "native-memory benchmark demonstrates the adjacent authorization overwrite and safe rejection",
  async () => {
    expect(compiler).not.toBeNull();
    const root = await mkdtemp(
      join(tmpdir(), "copilot-security-native-benchmark-"),
    );
    temporaryPaths.push(root);
    const harness = join(root, "harness.c");
    await writeFile(
      harness,
      [
        "#include <stddef.h>",
        "#include <stdint.h>",
        "#include <string.h>",
        "",
        "void handle_login_packet(const uint8_t *packet,",
        "                         size_t packet_size,",
        "                         void (*grant_admin)(void *),",
        "                         void *peer);",
        "",
        "static int admin_granted = 0;",
        "",
        "static void record_admin_grant(void *peer) {",
        "    (void)peer;",
        "    admin_granted = 1;",
        "}",
        "",
        "int main(void) {",
        "    uint8_t packet[35] = {0};",
        "    packet[0] = 0;",
        "    packet[1] = 33;",
        "    memset(packet + 2, 'A', 33);",
        "    packet[34] = 1;",
        "    handle_login_packet(packet, sizeof(packet), record_admin_grant, NULL);",
        "    return admin_granted == EXPECT_ADMIN_GRANT ? 0 : 1;",
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
      join(fixtures, "c-packet-length-overflow", "src", "session.c"),
      harness,
      join(root, executableName("vulnerable")),
      1,
    );
    compileAndRun(
      compiler!,
      join(fixtures, "c-bounded-packet-copy", "src", "session.c"),
      harness,
      join(root, executableName("safe")),
      0,
    );
  },
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
  expectedAdminGrant: 0 | 1,
): void {
  const compilation = spawnSync(
    compilerPath,
    [
      "-std=c11",
      "-Wall",
      "-Wextra",
      "-Werror",
      `-DEXPECT_ADMIN_GRANT=${expectedAdminGrant}`,
      source,
      harness,
      "-o",
      executable,
    ],
    { encoding: "utf8", windowsHide: true },
  );
  expect({
    status: compilation.status,
    stdout: compilation.stdout,
    stderr: compilation.stderr,
  }).toEqual({ status: 0, stdout: "", stderr: "" });

  const execution = spawnSync(executable, [], {
    encoding: "utf8",
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
