const account = {
  username: "guest",
  displayName: "Guest",
  mfaSecret: "enrolled-secret",
  role: "guest",
};

function applySafeReplacement(document) {
  return {
    username: "guest",
    displayName: document.displayName,
    mfaSecret: "server-managed",
    role: "guest",
  };
}

const replacement = applySafeReplacement({
  displayName: "Guest User",
  mfaSecret: "attacker-secret",
  role: "admin",
});
Object.assign(account, replacement);
if (account.role !== "guest" || account.mfaSecret !== "server-managed") {
  throw new Error("protected fields crossed the fixed replacement projection");
}
if (account.displayName !== "Guest User") {
  throw new Error("legitimate display-name replacement failed");
}
console.log("safe bulk replacement retained server-owned role and MFA");
