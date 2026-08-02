import { runHostCheck } from "./runner.js";

export function dispatchHostCheck(host, response) {
  return runHostCheck(host, response);
}
