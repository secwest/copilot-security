import deepExtend from "deep-extend";

export function buildOptions(patch) {
  return deepExtend({ mode: "strict" }, patch);
}
