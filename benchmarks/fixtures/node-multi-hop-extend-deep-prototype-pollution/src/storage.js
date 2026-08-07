import extend from "extend";

export function buildOptions(patch) {
  return extend(true, { mode: "strict" }, patch);
}
