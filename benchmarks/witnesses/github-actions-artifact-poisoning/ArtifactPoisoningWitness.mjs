import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const witnessDirectory = fileURLToPath(new URL(".", import.meta.url));
const repository = resolve(witnessDirectory, "..", "..", "..");

async function workflows(fixture) {
  const root = join(repository, "benchmarks", "fixtures", fixture);
  return {
    producer: await readFile(
      join(root, ".github", "workflows", "pr-build.yml"),
      "utf8",
    ),
    consumer: await readFile(
      join(root, ".github", "workflows", "publish.yml"),
      "utf8",
    ),
  };
}

const vulnerable = await workflows("github-actions-artifact-poisoning");
const safe = await workflows("github-actions-safe-artifact-data");
for (const pair of [vulnerable, safe]) {
  assert.match(pair.producer, /on:\s*\n\s*pull_request:/u);
  assert.match(pair.producer, /actions\/upload-artifact@v4/u);
  assert.match(pair.producer, /name:\s*release-input/u);
  assert.match(pair.consumer, /workflow_run:/u);
  assert.match(pair.consumer, /workflows:\s*\[PR Build\]/u);
  assert.match(pair.consumer, /github\.event\.workflow_run\.id/u);
}
assert.match(vulnerable.consumer, /path:\s*\.\s*$/mu);
assert.match(vulnerable.consumer, /run:\s*node release\.mjs/u);
assert.match(safe.consumer, /path:\s*\$\{\{ runner\.temp \}\}\/artifacts/u);
assert.match(safe.consumer, /Number\.isInteger\(releaseNumber\)/u);

const root = await mkdtemp(
  join(tmpdir(), "copilot-security-artifact-poisoning-"),
);
try {
  const artifact = join(root, "artifact", "release.mjs");
  const vulnerableWorkspace = join(root, "vulnerable-workspace");
  const safeExtraction = join(root, "safe-artifacts");
  const vulnerableMarker = join(root, "vulnerable-marker.txt");
  const safeMarker = join(root, "safe-marker.txt");
  await mkdir(join(root, "artifact"), { recursive: true });
  await mkdir(vulnerableWorkspace, { recursive: true });
  await mkdir(safeExtraction, { recursive: true });
  await writeFile(
    artifact,
    `import { writeFileSync } from "node:fs";\nwriteFileSync(process.argv[2], process.env.RELEASE_TOKEN ?? "missing");\n`,
  );
  await writeFile(
    join(vulnerableWorkspace, "release.mjs"),
    "throw new Error('trusted release script was not replaced');\n",
  );

  await copyFile(artifact, join(vulnerableWorkspace, "release.mjs"));
  const executed = spawnSync(
    process.execPath,
    [join(vulnerableWorkspace, "release.mjs"), vulnerableMarker],
    {
      cwd: vulnerableWorkspace,
      env: { RELEASE_TOKEN: "witness-only-release-token" },
      stdio: "pipe",
      timeout: 10_000,
      windowsHide: true,
    },
  );
  assert.equal(executed.status, 0);
  assert.equal(
    await readFile(vulnerableMarker, "utf8"),
    "witness-only-release-token",
  );

  const safeArtifact = join(safeExtraction, "release.mjs");
  await copyFile(artifact, safeArtifact);
  const raw = (await readFile(safeArtifact, "utf8")).trim();
  const releaseNumber = Number(raw);
  assert.equal(Number.isInteger(releaseNumber), false);
  await assert.rejects(readFile(safeMarker), { code: "ENOENT" });
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log(
  "The poisoned artifact executed with a mock privileged token; isolated typed-data validation rejected the same attacker bytes.",
);
