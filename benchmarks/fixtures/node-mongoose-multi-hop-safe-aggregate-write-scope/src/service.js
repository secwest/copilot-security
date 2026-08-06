import { aggregateAccountMaintenance } from "./storage.js";

export async function maintainAccounts(criteria) {
  return aggregateAccountMaintenance(criteria);
}
