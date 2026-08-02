import {
  chmod,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function resolveWithPython(
  python: string,
  repository: string,
  configuredGit: string,
  path: string,
): string | null {
  const program = [
    "import json, sys",
    "sys.path.insert(0, sys.argv[1])",
    "from workbench_constants import trusted_git_executable",
    "print(json.dumps(trusted_git_executable()))",
  ].join("\n");
  const result = Bun.spawnSync(
    [python, "-I", "-B", "-c", program, join(PLUGIN_ROOT, "scripts")],
    {
      stdout: "pipe",
      stderr: "pipe",
      env: {
        ...process.env,
        COPILOT_SECURITY_REPOSITORY: repository,
        COPILOT_SECURITY_GIT_PATH: configuredGit,
        PATH: path,
      },
    },
  );
  expect(new TextDecoder().decode(result.stderr)).toBe("");
  expect(result.exitCode).toBe(0);
  return JSON.parse(new TextDecoder().decode(result.stdout)) as string | null;
}

describe("workbench trusted executable resolution", () => {
  test("rejects target-supplied Git and accepts the canonical host executable", async () => {
    const python =
      Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
    const git = Bun.which("git");
    expect(python).not.toBeNull();
    expect(git).not.toBeNull();
    if (python === null || git === null) return;

    const root = await realpath(
      await mkdtemp(join(tmpdir(), "copilot-security-workbench-git-")),
    );
    temporaryDirectories.push(root);
    const repository = join(root, "repository");
    await mkdir(repository);
    const maliciousGit = join(
      repository,
      process.platform === "win32" ? "git.exe" : "git",
    );
    await writeFile(maliciousGit, "untrusted executable fixture\n");
    if (process.platform !== "win32") await chmod(maliciousGit, 0o700);

    expect(
      resolveWithPython(python, repository, maliciousGit, repository),
    ).toBeNull();

    const canonicalGit = await realpath(git);
    expect(
      resolveWithPython(
        python,
        repository,
        canonicalGit,
        dirname(canonicalGit),
      ),
    ).toBe(canonicalGit);
  });
});
