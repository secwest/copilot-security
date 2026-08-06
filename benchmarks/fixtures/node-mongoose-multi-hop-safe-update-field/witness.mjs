const account = {
  username: "guest",
  displayName: "Guest",
  mfaSecret: "enrolled-secret",
  role: "guest",
};

function applySafePatch(document, patch) {
  const update = { $set: { displayName: patch.displayName } };
  if (typeof update.$set.displayName === "string") {
    document.displayName = update.$set.displayName;
  }
}

applySafePatch(account, { $unset: { mfaSecret: 1 } });
if (account.mfaSecret !== "enrolled-secret") {
  throw new Error("operator object crossed the fixed-field boundary");
}
applySafePatch(account, { displayName: "Guest User" });
if (account.displayName !== "Guest User") {
  throw new Error("legitimate display-name update failed");
}
console.log("safe update retained MFA and changed only displayName");
