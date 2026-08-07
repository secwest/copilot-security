import merge from "merge";

export function buildOptions(patch) {
  return merge.recursive({ deep: {} }, patch);
}
