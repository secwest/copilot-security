import extend from "node.extend";

export function buildOptions(patch) {
  return extend(true, { mode: "strict" }, patch);
}
