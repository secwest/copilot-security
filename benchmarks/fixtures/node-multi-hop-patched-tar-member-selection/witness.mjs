import { dirname, parse } from "node:path";

const selected = new Map([["manifest.json", true]]);
const MAX_DEPTH = 100;
function mapHas(file, root = "", depth = 0) {
  if (depth >= MAX_DEPTH) {
    selected.set(file, false);
    return false;
  }
  root ||= parse(file).root || ".";
  if (file === root) return false;
  const known = selected.get(file);
  const result =
    known !== undefined ? known : mapHas(dirname(file), root, depth + 1);
  selected.set(file, result);
  return result;
}

const longPath = `${Array.from({ length: 12000 }, () => "a").join("/")}/payload`;
if (mapHas(longPath) !== false) {
  throw new Error("the bounded member filter accepted an unrelated long path");
}
console.log("patched node-tar member-selection recursion bound reproduced");
