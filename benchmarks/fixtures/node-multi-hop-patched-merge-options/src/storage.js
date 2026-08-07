import mergeOptions from "merge-options";

export function buildOptions(patch) {
  return mergeOptions({ mode: "strict" }, patch);
}
