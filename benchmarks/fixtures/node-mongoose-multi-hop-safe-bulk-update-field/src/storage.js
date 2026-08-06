import mongoose from "mongoose";

const ACCOUNT_SCHEMA = new mongoose.Schema({
  username: { type: String, required: true },
  displayName: { type: String, required: true },
  mfaSecret: { type: String, required: true },
  role: { type: String, required: true },
});
const Account = mongoose.model("Account", ACCOUNT_SCHEMA);

export async function persistAccountPatch(patch) {
  return Account.bulkWrite([
    {
      updateOne: {
        filter: { username: "guest" },
        update: { $set: { displayName: patch.displayName } },
      },
    },
  ]);
}
