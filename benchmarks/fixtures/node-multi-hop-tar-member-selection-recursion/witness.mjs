import { spawnSync } from "node:child_process";

const program = String.raw`
  const path = require("node:path");
  const selected = new Map([["manifest.json", true]]);
  const mapHas = (file, root = "") => {
    root ||= path.parse(file).root || ".";
    if (file === root) return false;
    const known = selected.get(file);
    const result = known !== undefined ? known : mapHas(path.dirname(file), root);
    selected.set(file, result);
    return result;
  };
  mapHas(Array.from({ length: 12000 }, () => "a").join("/") + "/payload");
`;
const result = spawnSync(process.execPath, ["-e", program], {
  encoding: "utf8",
  timeout: 10_000,
});
if (
  result.status === 0 ||
  !/Maximum call stack size exceeded/u.test(result.stderr)
) {
  throw new Error(
    "the vulnerable recursive member filter did not exhaust the child stack",
  );
}
console.log("vulnerable node-tar member-selection recursion reproduced");
