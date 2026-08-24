import assert from "node:assert/strict";
import { execSync } from "node:child_process";
import { readFile } from "node:fs/promises";
import { Shescape } from "shescape";

const manifest = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url), "utf8"),
);
const version = manifest.dependencies.shescape;
const vulnerable = version === "3.0.0";
const payload = "x) else if a==a (echo y";
const options = { shell: "cmd.exe", windowsHide: true };
const escaped =
  process.platform === "win32"
    ? new Shescape(options).escape(payload)
    : (
        await import(
          new URL("./internal/win/cmd.js", import.meta.resolve("shescape"))
        )
      ).getEscapeFunction()(payload);

assert.equal(escaped.includes("^)"), !vulnerable);
assert.equal(escaped.includes("^("), !vulnerable);

let stdout = "not-executed-on-this-platform";
if (process.platform === "win32") {
  stdout = execSync(`if defined FALSY (echo ${escaped})`, {
    ...options,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
  assert.equal(stdout, vulnerable ? "y" : "");
}

process.stdout.write(
  `${JSON.stringify({ version, vulnerable, escaped, stdout })}\n`,
);
