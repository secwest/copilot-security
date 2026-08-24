const requests = [
  "/foo/../deep/secret.txt",
  "/foo/%2e%2e/deep/secret.txt",
  "/foo/%2E%2E/deep/secret.txt",
];
const nonLeadingParent = /(?:^|[\\/])\.\.(?:[\\/]|$)/u;
const leadingParent = /^\/?\.\.(?:[\\/]|$)/u;

for (const requestPath of requests) {
  const decoded = decodeURI(requestPath);
  if (!nonLeadingParent.test(decoded) || leadingParent.test(decoded)) {
    throw new Error("the repaired raw-path guard did not reject the bypass");
  }
}

console.log("repaired Fastify Static parent-segment rejection reproduced");
