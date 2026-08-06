import { aggregateAccounts } from "./storage.js";

export async function viewAccounts(criteria) {
  return aggregateAccounts(criteria);
}
