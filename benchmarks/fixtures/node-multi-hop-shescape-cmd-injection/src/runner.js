import { execSync } from "node:child_process";
import { Shescape } from "shescape";

const options = { shell: "cmd.exe", windowsHide: true };
const escaper = new Shescape(options);

export function runCommand(value) {
  const escaped = escaper.escape(value);
  const command = `if defined FALSY (echo ${escaped})`;
  return execSync(command, options);
}
