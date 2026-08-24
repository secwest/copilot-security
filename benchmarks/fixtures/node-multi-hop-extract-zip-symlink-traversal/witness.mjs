import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

const extractionRoot = resolve("sandbox", "plugins");
const linkPath = join(extractionRoot, "current");
const protectedFile = resolve("sandbox", "protected", "config.json");
const linkPayload = relative(dirname(linkPath), dirname(protectedFile));
const memberRelative = relative(extractionRoot, linkPath);

if (
  memberRelative === ".." ||
  memberRelative.startsWith(`..${sep}`) ||
  isAbsolute(memberRelative)
) {
  throw new Error("the archive member name was not contained");
}

const readThroughLink = resolve(dirname(linkPath), linkPayload, "config.json");
if (readThroughLink !== protectedFile) {
  throw new Error("the symlink payload did not cross the extraction boundary");
}

console.log("vulnerable extract-zip symlink disclosure reproduced");
