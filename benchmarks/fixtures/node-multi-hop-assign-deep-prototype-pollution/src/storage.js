import assignDeep from "assign-deep";

export function buildOptions(patch) {
  return assignDeep({ mode: "strict" }, patch);
}
