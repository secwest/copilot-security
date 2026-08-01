import { execFile } from "node:child_process";

const EXECUTION_OPTIONS = Object.freeze({
  shell: false,
  timeout: 1_000,
  maxBuffer: 1_024,
  windowsHide: true,
});

let activeChecks = 0;

export function runHostCheck(host, response) {
  if (activeChecks >= 1) return response.status(429).end();
  activeChecks += 1;

  const done = (error) => {
    activeChecks -= 1;
    if (error) return response.status(502).end();
    return response.json({ status: "ok" });
  };

  return execFile(process.execPath, ["-e", "0", host], EXECUTION_OPTIONS, done);
}
