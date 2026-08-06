import mongoose from "mongoose";

const ACCOUNT_SCHEMA = new mongoose.Schema({
  username: { type: String, required: true },
  role: { type: String, required: true },
});
const Account = mongoose.model("Account", ACCOUNT_SCHEMA);

export async function loadAccount(selector) {
  return Account.findOne({ username: selector }).lean().exec();
}
