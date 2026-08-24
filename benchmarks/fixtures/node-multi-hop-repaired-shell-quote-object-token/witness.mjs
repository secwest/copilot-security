import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";

const require = createRequire(import.meta.url);
const { quote } = require("shell-quote");
const { version } = require("shell-quote/package.json");
const payload = ";\npwd";

let command = null;
let error = null;
let shellOutput = null;
try {
  command = quote([{ op: payload }]);
  if (process.platform !== "win32") {
    shellOutput = execFileSync("/bin/sh", ["-c", command], {
      cwd: tmpdir(),
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  }
} catch (caught) {
  error = caught instanceof Error ? caught.message : String(caught);
}

const vulnerable = version === "1.8.3";
const separatorRetained = command?.includes("\n") === true;
const rejected = error?.startsWith("invalid `op` value:") === true;
const boundedShellEffect =
  process.platform === "win32" ||
  (typeof shellOutput === "string" && shellOutput.length > 0);
if (
  (vulnerable && (!separatorRetained || !boundedShellEffect)) ||
  (!vulnerable && !rejected)
) {
  throw new Error(
    `Unexpected shell-quote boundary for ${version}: command=${command}, error=${error}, shellOutput=${shellOutput}`,
  );
}
console.log(
  JSON.stringify({
    version,
    separatorRetained,
    rejected,
    shellOutput,
    command,
    error,
  }),
);
