import merge from "lodash.merge";

export function buildOptions(patch) {
  return merge({ mode: "strict" }, patch);
}
