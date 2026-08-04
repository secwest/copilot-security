import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

const witnessDirectory = fileURLToPath(new URL(".", import.meta.url));
const repository = resolve(witnessDirectory, "..", "..", "..");
const titleExpression = "${{ github.event.pull_request.title }}";
const mockToken = "witness-only-release-token";
const payload = '"); core.info("LEAK:" + process.env.RELEASE_TOKEN); //';

async function workflow(fixture) {
  return readFile(
    join(
      repository,
      "benchmarks",
      "fixtures",
      fixture,
      ".github",
      "workflows",
      "check-title.yml",
    ),
    "utf8",
  );
}

function scriptFrom(source) {
  const block = /\n\s+script:\s*\|\s*\r?\n([\s\S]+)$/u.exec(source)?.[1];
  assert.ok(block, "the fixture must end with a github-script block");
  const indents = block
    .split(/\r?\n/u)
    .filter((line) => line.trim() !== "")
    .map((line) => /^\s*/u.exec(line)?.[0].length ?? 0);
  const indent = Math.min(...indents);
  return block
    .split(/\r?\n/u)
    .map((line) => line.slice(Math.min(indent, line.length)))
    .join("\n")
    .trim();
}

function execute(script, environment) {
  const messages = [];
  runInNewContext(script, {
    core: { info: (message) => messages.push(String(message)) },
    process: { env: environment },
  });
  return messages;
}

const vulnerable = await workflow("github-actions-workflow-script-injection");
const safe = await workflow("github-actions-safe-workflow-script-input");
for (const source of [vulnerable, safe]) {
  assert.match(source, /on:\s*\r?\n\s*pull_request_target:/u);
  assert.match(source, /actions\/github-script@v8/u);
  assert.match(source, /RELEASE_TOKEN:\s*\$\{\{ secrets\.RELEASE_TOKEN \}\}/u);
}

const vulnerableScript = scriptFrom(vulnerable).replaceAll(
  titleExpression,
  payload,
);
const vulnerableMessages = execute(vulnerableScript, {
  RELEASE_TOKEN: mockToken,
});
assert.deepEqual(vulnerableMessages, ["Checking ", `LEAK:${mockToken}`]);

assert.doesNotMatch(scriptFrom(safe), /\$\{\{\s*github\.event/u);
assert.match(safe, /TITLE:\s*\$\{\{ github\.event\.pull_request\.title \}\}/u);
const safeMessages = execute(scriptFrom(safe), {
  TITLE: payload,
  RELEASE_TOKEN: mockToken,
});
assert.deepEqual(safeMessages, [`Checking ${payload}`]);
assert.equal(safeMessages.includes(`LEAK:${mockToken}`), false);

console.log(
  "Direct event-field substitution executed injected JavaScript; the intermediate environment value stayed inert.",
);
