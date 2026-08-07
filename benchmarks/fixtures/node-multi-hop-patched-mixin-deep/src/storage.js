import mixinDeep from "mixin-deep";

export function buildOptions(patch) {
  return mixinDeep({ mode: "strict" }, patch);
}
