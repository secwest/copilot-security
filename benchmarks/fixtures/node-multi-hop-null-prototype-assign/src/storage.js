const DEFAULT_MODE = "strict";

export function buildOptions(patch) {
  const options = Object.assign(
    Object.create(null),
    { mode: DEFAULT_MODE },
    patch,
  );
  return options;
}
