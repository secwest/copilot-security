import { aggregateAccountMaintenance } from "./storage.js";

export async function maintainAccounts(pipeline) {
  return aggregateAccountMaintenance(pipeline);
}
