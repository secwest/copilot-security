import { maintainAccounts } from "./service.js";

export async function routeAccountMaintenance(stages) {
  return maintainAccounts(stages);
}
