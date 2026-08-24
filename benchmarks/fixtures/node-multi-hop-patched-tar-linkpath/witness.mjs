import { posix } from "node:path";

const extractionRoot = "/srv/imports";
const linkDirectory = `${extractionRoot}/a/b`;
const rawLinkpath = "C:../../../secret.txt";
const rewritten = rawLinkpath.replace(/^[A-Za-z]:/u, "");
const target = posix.resolve(linkDirectory, rewritten);

if (target.startsWith(`${extractionRoot}/`)) {
  throw new Error("the repaired pre-creation check missed parent traversal");
}

console.log("patched node-tar rejects the rewritten linkpath");
