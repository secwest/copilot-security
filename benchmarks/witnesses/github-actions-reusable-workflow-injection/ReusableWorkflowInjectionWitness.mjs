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

async function workflows(fixture) {
  const root = join(repository, "benchmarks", "fixtures", fixture);
  return {
    caller: await readFile(
      join(root, ".github", "workflows", "comment-release.yml"),
      "utf8",
    ),
    called: await readFile(
      join(root, ".github", "workflows", "reusable-release.yml"),
      "utf8",
    ),
  };
}

function scriptFrom(workflow) {
  const block = /\n\s+script:\s*\|\s*\r?\n([\s\S]+)$/u.exec(workflow)?.[1];
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

const vulnerable = await workflows(
  "github-actions-reusable-workflow-injection",
);
const safe = await workflows("github-actions-safe-reusable-workflow-input");
for (const pair of [vulnerable, safe]) {
  assert.match(pair.caller, /on:\s*\r?\n\s*issue_comment:/u);
  assert.match(
    pair.caller,
    /uses:\s*\.\/\.github\/workflows\/reusable-release\.yml/u,
  );
  assert.match(
    pair.caller,
    /release-name:\s*\$\{\{ github\.event\.comment\.body \}\}/u,
  );
  assert.match(pair.called, /workflow_call:/u);
  assert.match(pair.called, /release-name:\s*\r?\n\s*required:\s*true/u);
  assert.match(pair.called, /type:\s*string/u);
  assert.match(pair.called, /actions\/github-script@v8/u);
}

const vulnerableScript = scriptFrom(vulnerable.called).replaceAll(
  inputExpression,
  payload,
);
const vulnerableMessages = execute(vulnerableScript, {
  RELEASE_TOKEN: mockToken,
});
assert.deepEqual(vulnerableMessages, ["Publishing ", `LEAK:${mockToken}`]);

assert.doesNotMatch(scriptFrom(safe.called), /\$\{\{\s*inputs\./u);
assert.match(safe.called, /RELEASE_NAME:\s*\$\{\{ inputs\.release-name \}\}/u);
const safeMessages = execute(scriptFrom(safe.called), {
  RELEASE_NAME: payload,
  RELEASE_TOKEN: mockToken,
});
assert.equal(safeMessages.length, 1);
assert.equal(safeMessages[0], `Publishing ${payload}`);
assert.equal(safeMessages.includes(`LEAK:${mockToken}`), false);

console.log(
  "Direct workflow-expression substitution executed the injected JavaScript; process.env kept the same payload inert.",
);
