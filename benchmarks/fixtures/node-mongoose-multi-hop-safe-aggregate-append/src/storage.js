import mongoose from "mongoose";

const ACCOUNT_SCHEMA = new mongoose.Schema({
  username: { type: String, required: true },
  displayName: { type: String, required: true },
  active: { type: Boolean, required: true },
});
const Account = mongoose.model("Account", ACCOUNT_SCHEMA);

export async function aggregateAccounts(criteria) {
  const aggregate = Account.aggregate([{ $match: { active: true } }]);
  aggregate.append({ $match: { username: { $eq: criteria.username } } });
  aggregate.append({ $project: { username: 1, displayName: 1 } });
  return aggregate.exec();
}
