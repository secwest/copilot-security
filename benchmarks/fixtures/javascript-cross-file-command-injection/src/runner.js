import { exec } from "node:child_process";

export function runHostCheck(host, response) {
  return exec(`ping -n 1 ${host}`, (error, stdout) =>
    response.json({ error: error?.message, stdout }),
  );
}
