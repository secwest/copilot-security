import { VM } from "vm2";
const sandbox = new VM();

export function runInSandbox(code) {
  return sandbox.run(code);
}
