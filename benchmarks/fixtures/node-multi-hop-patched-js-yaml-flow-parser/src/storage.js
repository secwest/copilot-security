import { load } from "js-yaml";

export function loadDocument(source) {
  return load(source, { maxDepth: 100 });
}
