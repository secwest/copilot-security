const DEFAULT_MODE = "strict";

export function buildOptions(patch) {
  const options = Object.assign({ mode: DEFAULT_MODE }, patch);
  return options;
}
