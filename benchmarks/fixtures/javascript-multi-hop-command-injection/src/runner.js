import { exec } from "node:child_process";

export function runHostCheck(host, response) {
  return exec(`ping -n 1 ${host}`, (_error, stdout) => response.send(stdout));
}
