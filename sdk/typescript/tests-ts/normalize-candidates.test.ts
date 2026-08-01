import {
  mkdtemp,
  mkdir,
  readFile,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
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

async function temporaryDirectory(): Promise<string> {
  const path = await realpath(
    await mkdtemp(join(tmpdir(), "copilot-security-candidate-test-")),
  );
  temporaryDirectories.push(path);
  return path;
}

function candidate(path: string, instance: string): Record<string, unknown> {
  return {
    cwe_ids: ["CWE-78"],
    locations: [{ path, start_line: 1, end_line: 1, role: "evidence" }],
    summary: "External candidate",
    evidence: "Requires independent validation",
    context: "tool=example",
    instance,
  };
}

async function runNormalizer(
  repository: string,
  input: string,
  seedInput: string,
  scope: string,
  output: string,
): Promise<ReturnType<typeof Bun.spawnSync>> {
  const python = Bun.which("python3") ?? Bun.which("python") ?? Bun.which("py");
  expect(python).not.toBeNull();
  return Bun.spawnSync([
    python!,
    "-I",
    "-B",
    join(PLUGIN_ROOT, "scripts", "normalize_candidates.py"),
    "--input",
    input,
    "--seed-input",
    seedInput,
    "--out",
    output,
    "--repo-root",
    repository,
    "--in-scope-files",
    scope,
  ]);
}

describe("candidate normalization", () => {
  test("imports in-scope SARIF seeds and deterministically skips scoped-out rows", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(join(repository, "src"), { recursive: true });
    await mkdir(join(repository, "other"), { recursive: true });
    await writeFile(join(repository, "src", "included.ts"), "included\n");
    await writeFile(join(repository, "other", "outside.ts"), "outside\n");
    const input = join(root, "native.jsonl");
    const seedInput = join(root, "seeds.jsonl");
    const scope = join(root, "scope.txt");
    const output = join(root, "candidate_ledger.jsonl");
    await writeFile(
      input,
      `${JSON.stringify(candidate("src/included.ts", "native"))}\n`,
    );
    await writeFile(
      seedInput,
      [
        candidate("src/included.ts", "seed-in-scope"),
        candidate("other/outside.ts", "seed-out-of-scope"),
      ]
        .map((row) => JSON.stringify(row))
        .join("\n") + "\n",
    );
    await writeFile(scope, "src/included.ts\n");

    const result = await runNormalizer(
      repository,
      input,
      seedInput,
      scope,
      output,
    );
    expect(result.exitCode).toBe(0);
    expect(result.stdout?.toString() ?? "").toContain(
      "skipped 1 out-of-scope seed rows",
    );
    const rows = (await readFile(output, "utf8"))
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line));
    expect(rows).toHaveLength(2);
    expect(rows.map((row) => row.instance).sort()).toEqual([
      "native",
      "seed-in-scope",
    ]);
  });

  test("does not let malformed seed rows hide outside scope", async () => {
    const root = await temporaryDirectory();
    const repository = join(root, "repository");
    await mkdir(join(repository, "src"), { recursive: true });
    await mkdir(join(repository, "other"), { recursive: true });
    await writeFile(join(repository, "src", "included.ts"), "included\n");
    await writeFile(join(repository, "other", "outside.ts"), "outside\n");
    const input = join(root, "native.jsonl");
    const seedInput = join(root, "seeds.jsonl");
    const scope = join(root, "scope.txt");
    const output = join(root, "candidate_ledger.jsonl");
    await writeFile(
      input,
      `${JSON.stringify(candidate("src/included.ts", "native"))}\n`,
    );
    await writeFile(
      seedInput,
      `${JSON.stringify({ ...candidate("other/outside.ts", "bad"), injected: true })}\n`,
    );
    await writeFile(scope, "src/included.ts\n");

    const result = await runNormalizer(
      repository,
      input,
      seedInput,
      scope,
      output,
    );
    expect(result.exitCode).toBe(2);
    expect(result.stderr?.toString() ?? "").toContain(
      "unsupported fields injected",
    );
  });
});
