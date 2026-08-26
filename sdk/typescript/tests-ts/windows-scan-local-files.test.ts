import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const python = Bun.which("python3") ?? Bun.which("python");
const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("Windows scan-local file backend", () => {
  test.skipIf(process.platform !== "win32" || python === null)(
    "uses zero-access ancestor handles and preserves secure file operations",
    async () => {
      const root = await mkdtemp(
        join(tmpdir(), "copilot-security-windows-scan-files-"),
      );
      temporaryDirectories.push(root);
      await mkdir(join(root, "artifacts"));
      await writeFile(join(root, "artifacts", "input.txt"), "original\n");

      const helper = join(
        PLUGIN_ROOT,
        "scripts",
        "windows_scan_local_files.py",
      );
      const script = String.raw`
import importlib.util
import os
import pathlib
import sys

helper = pathlib.Path(sys.argv[1])
root = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location("copilot_security_windows_scan_files_test", helper)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

captured = []
original_create_file = module._create_file
original_verify_directory = module._verify_directory

class FakeHandle:
    value = 123
    def close(self):
        pass

def capture_create_file(path, *, access, share, disposition, flags, missing_ok=False):
    captured.append(access)
    return FakeHandle()

module._create_file = capture_create_file
module._verify_directory = lambda handle, path: None
try:
    module._open_directory(root)
finally:
    module._create_file = original_create_file
    module._verify_directory = original_verify_directory
assert captured == [0], captured

descriptor = module.open_read_fd(root, "artifacts/input.txt", "test input")
try:
    assert os.read(descriptor, 32) == b"original\n"
finally:
    os.close(descriptor)
module.atomic_write(root, "artifacts/output.txt", b"replacement\n")
module.unlink_if_exists(root, "artifacts/input.txt")
`;
      const result = spawnSync(
        python!,
        ["-I", "-B", "-c", script, helper, root],
        {
          encoding: "utf8",
          windowsHide: true,
        },
      );

      expect(result.status, `${result.stdout}\n${result.stderr}`).toBe(0);
      expect(
        await readFile(join(root, "artifacts", "output.txt"), "utf8"),
      ).toBe("replacement\n");
      await expect(
        readFile(join(root, "artifacts", "input.txt"), "utf8"),
      ).rejects.toMatchObject({ code: "ENOENT" });
    },
  );
});
