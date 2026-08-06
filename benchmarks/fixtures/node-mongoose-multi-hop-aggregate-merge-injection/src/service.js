import { aggregateAccountMaintenance } from "./storage.js";

export async function maintainAccounts(stages) {
  return aggregateAccountMaintenance(stages);
}
