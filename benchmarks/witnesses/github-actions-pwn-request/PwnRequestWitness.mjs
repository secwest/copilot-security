import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const witnessDirectory = fileURLToPath(new URL(".", import.meta.url));
const repository = resolve(witnessDirectory, "..", "..", "..");
const vulnerableWorkflow = await readFile(
  join(
    repository,
    "benchmarks",
    "fixtures",
    "github-actions-pwn-request",
    ".github",
    "workflows",
    "ci.yml",
  ),
  "utf8",
);
const protectedWorkflow = await readFile(
  join(
    repository,
    "benchmarks",
    "fixtures",
    "github-actions-safe-pr-checkout",
    ".github",
    "workflows",
    "ci.yml",
  ),
  "utf8",
);

function forkCheckoutAllowed(workflow) {
  const version = Number.parseInt(
    /actions\/checkout@v(\d+)/u.exec(workflow)?.[1] ?? "0",
    10,
  );
  return version < 7 || /allow-unsafe-pr-checkout:\s*true\b/iu.test(workflow);
}

const root = await mkdtemp(join(tmpdir(), "copilot-security-pwn-request-"));
try {
  const attackerProgram = join(root, "attacker.mjs");
  const vulnerableMarker = join(root, "vulnerable-marker.txt");
  const protectedMarker = join(root, "protected-marker.txt");
  await writeFile(
    attackerProgram,
    `import { writeFileSync } from "node:fs";\nwriteFileSync(process.argv[2], process.env.RELEASE_TOKEN ?? "missing");\n`,
  );

  assert.equal(forkCheckoutAllowed(vulnerableWorkflow), true);
  const vulnerable = spawnSync(
    process.execPath,
    [attackerProgram, vulnerableMarker],
    {
      env: { RELEASE_TOKEN: "witness-only-privileged-token" },
      stdio: "pipe",
      timeout: 10_000,
      windowsHide: true,
    },
  );
  assert.equal(vulnerable.status, 0);
  assert.equal(
    await readFile(vulnerableMarker, "utf8"),
    "witness-only-privileged-token",
  );

  assert.equal(forkCheckoutAllowed(protectedWorkflow), false);
  assert.throws(() => {
    if (!forkCheckoutAllowed(protectedWorkflow)) {
      throw new Error("Checkout v7 refused fork pull-request code.");
    }
    spawnSync(process.execPath, [attackerProgram, protectedMarker]);
  }, /refused fork pull-request code/u);
  await assert.rejects(readFile(protectedMarker), { code: "ENOENT" });
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log(
  "Privileged fork code observed the mock token; Checkout v7 protection prevented the matched execution.",
);
