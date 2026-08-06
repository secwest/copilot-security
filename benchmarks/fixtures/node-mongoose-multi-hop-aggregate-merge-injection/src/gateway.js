import { maintainAccounts } from "./service.js";

export async function routeAccountMaintenance(pipeline) {
  return maintainAccounts(pipeline);
}
