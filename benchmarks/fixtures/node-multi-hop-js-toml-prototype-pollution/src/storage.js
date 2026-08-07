import { load } from "js-toml";

export function loadOptions(text) {
  return load(text);
}
