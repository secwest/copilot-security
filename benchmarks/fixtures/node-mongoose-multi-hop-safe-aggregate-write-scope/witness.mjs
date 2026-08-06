const accounts = [
  {
    _id: 1,
    username: "guest",
    mfaSecret: "enrolled-secret",
    role: "guest",
  },
];
const reviewedAccounts = [];

function safeMaintenance(criteria) {
  const selected = accounts.filter(
    (account) => account.username === criteria.username,
  );
  for (const account of selected) {
    reviewedAccounts.push({ ...account, reviewed: true });
  }
}

safeMaintenance({ username: { $ne: null }, into: "accounts" });
if (reviewedAccounts.length !== 0) {
  throw new Error("operator object crossed fixed aggregate match equality");
}
safeMaintenance({ username: "guest", into: "accounts" });
if (reviewedAccounts[0]?.reviewed !== true) {
  throw new Error("legitimate reviewed-account write failed");
}
if (
  accounts[0]?.role !== "guest" ||
  accounts[0]?.mfaSecret !== "enrolled-secret"
) {
  throw new Error("fixed aggregate write mutated protected account state");
}
console.log(
  "safe aggregate write retained protected state and fixed destination",
);
