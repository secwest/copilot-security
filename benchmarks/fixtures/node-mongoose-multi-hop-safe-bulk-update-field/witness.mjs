const account = {
  username: "guest",
  displayName: "Guest",
  mfaSecret: "enrolled-secret",
  role: "guest",
};

function applySafeBulkPatch(document, patch) {
  const operation = {
    updateOne: {
      filter: { username: "guest" },
      update: { $set: { displayName: patch.displayName } },
    },
  };
  if (typeof operation.updateOne.update.$set.displayName === "string") {
    document.displayName = operation.updateOne.update.$set.displayName;
  }
}

applySafeBulkPatch(account, { $unset: { mfaSecret: 1 } });
if (account.mfaSecret !== "enrolled-secret") {
  throw new Error("operator object crossed the fixed bulk-update boundary");
}
applySafeBulkPatch(account, { displayName: "Guest User" });
if (account.displayName !== "Guest User") {
  throw new Error("legitimate display-name update failed");
}
console.log("safe bulk update retained MFA and changed only displayName");
