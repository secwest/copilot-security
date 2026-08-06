import mongoose from "mongoose";

const ACCOUNT_SCHEMA = new mongoose.Schema({
  username: { type: String, required: true },
  displayName: { type: String, required: true },
  mfaSecret: { type: String, required: true },
  role: { type: String, required: true },
});
const Account = mongoose.model("Account", ACCOUNT_SCHEMA);

export async function aggregateAccounts(criteria) {
  return Account.aggregate([
    { $match: { username: { $eq: criteria.username } } },
    { $project: { username: 1, displayName: 1 } },
  ]).exec();
}
