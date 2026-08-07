import extend from "just-extend";

export function buildOptions(patch) {
  return extend(true, { mode: "strict" }, patch);
}
