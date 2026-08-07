import { dirname, isAbsolute, relative, sep } from "node:path";

const cssFile = "/srv/styles/input.css";
const candidate = "/srv/protected.map";
const path = relative(dirname(cssFile), candidate);
if (!(path === ".." || path.startsWith(`..${sep}`) || isAbsolute(path))) {
  throw new Error("patched containment did not reject the external map");
}
console.log("patched PostCSS previous-map containment reproduced");
