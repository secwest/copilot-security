import { aggregateAccounts } from "./storage.js";

export async function viewAccounts(stages) {
  return aggregateAccounts(stages);
}
