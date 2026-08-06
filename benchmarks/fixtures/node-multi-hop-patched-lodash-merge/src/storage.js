import lodash from "lodash";

export function buildOptions(patch) {
  return lodash.merge({ mode: "strict" }, patch);
}
