import mergeDeep from "merge-deep";

export function buildOptions(patch) {
  return mergeDeep({ mode: "strict" }, patch);
}
