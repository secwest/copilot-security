const account = {
  username: "guest",
  displayName: "Guest",
  mfaSecret: "enrolled-secret",
  role: "guest",
};
const attackerDocument = {
  username: "guest",
  displayName: "Guest",
  mfaSecret: "attacker-secret",
  role: "admin",
};

Object.assign(account, attackerDocument);
if (account.role !== "admin" || account.mfaSecret !== "attacker-secret") {
  throw new Error("bulk replacement mass assignment not reproduced");
}
console.log("vulnerable bulk replacement overwrote role and MFA");
