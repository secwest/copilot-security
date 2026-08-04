import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const witnessDirectory = fileURLToPath(new URL(".", import.meta.url));
const repository = resolve(witnessDirectory, "..", "..", "..");
const mockToken = "witness-only-release-token";

async function workflow(fixture) {
  return readFile(
    join(
      repository,
      "benchmarks",
      "fixtures",
      fixture,
      ".github",
      "workflows",
      "test.yml",
    ),
    "utf8",
  );
}

async function prepareRunner(root) {
  const helper = join(root, "tools", "release-helper.mjs");
  await mkdir(dirname(helper), { recursive: true });
  await writeFile(helper, 'console.log("trusted release helper");\n');
  return helper;
}

async function untrustedPullRequestJob(root) {
  const helper = join(root, "tools", "release-helper.mjs");
  await writeFile(
    helper,
    'console.log("OBSERVED:" + process.env.RELEASE_TOKEN);\n',
  );
}

function privilegedReleaseJob(helper) {
  return spawnSync(process.execPath, [helper], {
    encoding: "utf8",
    env: { ...process.env, RELEASE_TOKEN: mockToken },
  });
}

const vulnerable = await workflow("github-actions-self-hosted-pr-execution");
const safe = await workflow("github-actions-safe-hosted-pr-execution");
for (const source of [vulnerable, safe]) {
  assert.match(source, /on:\s*\r?\n\s*pull_request:/u);
  assert.match(source, /actions\/checkout@v6/u);
  assert.match(source, /persist-credentials:\s*false/u);
  assert.match(source, /run:\s*npm test/u);
}
assert.match(vulnerable, /runs-on:\s*\[self-hosted, linux, x64\]/u);
assert.match(safe, /runs-on:\s*ubuntu-latest/u);

const root = await mkdtemp(join(tmpdir(), "copilot-security-runner-witness-"));
try {
  const persistentRunner = join(root, "persistent");
  const persistentHelper = await prepareRunner(persistentRunner);
  await untrustedPullRequestJob(persistentRunner);
  const persistentRelease = privilegedReleaseJob(persistentHelper);
  assert.equal(persistentRelease.status, 0);
  assert.equal(persistentRelease.stdout.trim(), `OBSERVED:${mockToken}`);

  const pullRequestMachine = join(root, "hosted-pr-machine");
  await prepareRunner(pullRequestMachine);
  await untrustedPullRequestJob(pullRequestMachine);
  await rm(pullRequestMachine, { recursive: true, force: true });

  const freshReleaseMachine = join(root, "hosted-release-machine");
  const freshHelper = await prepareRunner(freshReleaseMachine);
  const isolatedRelease = privilegedReleaseJob(freshHelper);
  assert.equal(isolatedRelease.status, 0);
  assert.equal(isolatedRelease.stdout.trim(), "trusted release helper");
  assert.doesNotMatch(isolatedRelease.stdout, /OBSERVED:/u);
} finally {
  await rm(root, { recursive: true, force: true });
}

console.log(
  "The reusable runner carried attacker persistence into a later privileged job; the fresh hosted runner did not.",
);
