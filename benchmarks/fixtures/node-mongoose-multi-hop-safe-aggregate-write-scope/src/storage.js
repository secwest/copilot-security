import mongoose from "mongoose";

const ACCOUNT_SCHEMA = new mongoose.Schema({
  username: { type: String, required: true },
  displayName: { type: String, required: true },
  mfaSecret: { type: String, required: true },
  role: { type: String, required: true },
});
const Account = mongoose.model("Account", ACCOUNT_SCHEMA);

export async function aggregateAccountMaintenance(criteria) {
  return Account.aggregate([
    { $match: { username: { $eq: criteria.username } } },
    { $set: { reviewed: true } },
    {
      $merge: {
        into: "reviewedAccounts",
        on: "_id",
        whenMatched: "merge",
        whenNotMatched: "insert",
      },
    },
  ]).exec();
}
