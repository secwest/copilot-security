import { execFile } from "node:child_process";
import { quote } from "shell-quote";

export function runOperator(operator) {
  const command = quote([{ op: operator }]);
  return execFile("/bin/sh", ["-c", command]);
}
