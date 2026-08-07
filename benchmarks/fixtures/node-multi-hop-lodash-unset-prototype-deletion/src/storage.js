import unset from "lodash/unset.js";

export function deleteSetting(path) {
  return unset({}, path);
}
