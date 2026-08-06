import mongoose from "mongoose";

const ACCOUNT_SCHEMA = new mongoose.Schema({
  username: { type: String, required: true },
  displayName: { type: String, required: true },
  mfaSecret: { type: String, required: true },
  role: { type: String, required: true },
});
const Account = mongoose.model("Account", ACCOUNT_SCHEMA);

export async function persistAccountReplacement(document) {
  return Account.bulkWrite([
    {
      replaceOne: {
        filter: { username: "guest" },
        replacement: {
          username: "guest",
          displayName: document.displayName,
          mfaSecret: "server-managed",
          role: "guest",
        },
      },
    },
  ]);
}
