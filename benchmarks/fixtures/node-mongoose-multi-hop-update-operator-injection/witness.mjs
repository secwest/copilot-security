const account = {
  username: "guest",
  displayName: "Guest",
  mfaSecret: "enrolled-secret",
  role: "guest",
};

function applyUpdate(document, update) {
  for (const field of Object.keys(update.$unset ?? {})) delete document[field];
  Object.assign(document, update.$set ?? {});
}

applyUpdate(account, { $unset: { mfaSecret: 1 } });
if (Object.hasOwn(account, "mfaSecret")) {
  throw new Error("update-operator injection not reproduced");
}
if (account.role !== "guest") throw new Error("witness changed account role");
console.log("vulnerable update document removed the MFA secret");
