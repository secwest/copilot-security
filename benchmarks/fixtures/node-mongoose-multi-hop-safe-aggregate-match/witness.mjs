const accounts = [
  { username: "guest", displayName: "Guest", mfaSecret: "guest-secret" },
  {
    username: "admin",
    displayName: "Administrator",
    mfaSecret: "admin-secret",
  },
];

function safeReport(criteria) {
  return accounts
    .filter((account) => account.username === criteria.username)
    .map(({ username, displayName }) => ({ username, displayName }));
}

if (safeReport({ username: { $ne: null } }).length !== 0) {
  throw new Error("operator object crossed fixed aggregate match equality");
}
const result = safeReport({ username: "guest" });
if (result.length !== 1 || result[0]?.displayName !== "Guest") {
  throw new Error("legitimate aggregate lookup failed");
}
if (Object.hasOwn(result[0], "mfaSecret")) {
  throw new Error("public projection exposed the MFA secret");
}
console.log(
  "safe aggregate match rejected operators and projected public data",
);
