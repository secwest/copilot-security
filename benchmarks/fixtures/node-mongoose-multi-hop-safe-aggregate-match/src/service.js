import { aggregateAccounts } from "./storage.js";

export async function buildAccountReport(criteria) {
  return aggregateAccounts(criteria);
}
