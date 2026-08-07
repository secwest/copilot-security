import { mergeDeep } from "immutable";

export function buildProfile(update) {
  return mergeDeep({ name: "Alice", role: "user" }, update);
}
