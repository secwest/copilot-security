import { runInSandbox } from "./sandbox.js";

export function executeCode(code) {
  return runInSandbox(code);
}
