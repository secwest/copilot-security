import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { runInNewContext } from "node:vm";

const witnessDirectory = fileURLToPath(new URL(".", import.meta.url));
const repository = resolve(witnessDirectory, "..", "..", "..");
const inputExpression = "${{ inputs.release-name }}";
const mockToken = "witness-only-release-token";
const payload = '"); core.info("LEAK:" + process.env.RELEASE_TOKEN); //';

async function fixtureFiles(fixture) {
  const root = join(repository, "benchmarks", "fixtures", fixture);
  return {
    caller: await readFile(
      join(root, ".github", "workflows", "comment-release.yml"),
      "utf8",
    ),
    action: await readFile(
      join(root, ".github", "actions", "publish-release", "action.yml"),
      "utf8",
    ),
  };
}

function scriptFrom(action) {
  const block = /\n\s+script:\s*\|\s*\r?\n([\s\S]+)$/u.exec(action)?.[1];
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

const vulnerable = await fixtureFiles(
  "github-actions-composite-action-injection",
);
const safe = await fixtureFiles("github-actions-safe-composite-action-input");
for (const pair of [vulnerable, safe]) {
  assert.match(pair.caller, /on:\s*\r?\n\s*issue_comment:/u);
  assert.match(
    pair.caller,
    /uses:\s*\.\/\.github\/actions\/publish-release/u,
  );
  assert.match(
    pair.caller,
    /release-name:\s*\$\{\{ github\.event\.comment\.body \}\}/u,
  );
  assert.match(pair.action, /using:\s*composite/u);
  assert.match(pair.action, /release-name:\s*\r?\n\s*description:/u);
  assert.match(pair.action, /actions\/github-script@v8/u);
}

const vulnerableScript = scriptFrom(vulnerable.action).replaceAll(
  inputExpression,
  payload,
);
const vulnerableMessages = execute(vulnerableScript, {
  RELEASE_TOKEN: mockToken,
});
assert.deepEqual(vulnerableMessages, ["Publishing ", `LEAK:${mockToken}`]);

assert.doesNotMatch(scriptFrom(safe.action), /\$\{\{\s*inputs\.release-name/u);
assert.match(
  safe.action,
  /RELEASE_NAME:\s*\$\{\{ inputs\.release-name \}\}/u,
);
const safeMessages = execute(scriptFrom(safe.action), {
  RELEASE_NAME: payload,
  RELEASE_TOKEN: mockToken,
});
assert.equal(safeMessages.length, 1);
assert.equal(safeMessages[0], `Publishing ${payload}`);
assert.equal(safeMessages.includes(`LEAK:${mockToken}`), false);

console.log(
  "Composite expression substitution executed the injected JavaScript; the step environment kept the same input inert.",
);
