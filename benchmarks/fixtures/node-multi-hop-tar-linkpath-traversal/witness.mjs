import { posix } from "node:path";

const extractionRoot = "/srv/imports";
const linkDirectory = `${extractionRoot}/a/b`;
const rawLinkpath = "C:../../../secret.txt";

const validatedTarget = posix.resolve(linkDirectory, rawLinkpath);
if (!validatedTarget.startsWith(`${extractionRoot}/`)) {
  throw new Error("the pre-strip check unexpectedly saw an external target");
}
const rewritten = rawLinkpath.replace(/^[A-Za-z]:/u, "");
const target = posix.resolve(linkDirectory, rewritten);
if (target.startsWith(`${extractionRoot}/`)) {
  throw new Error("the vulnerable link target remained inside extraction");
}

console.log("vulnerable node-tar linkpath escape reproduced");
