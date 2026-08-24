import { runOperator } from "./runner.js";

export async function dispatchOperator(operator) {
  return runOperator(operator);
}
