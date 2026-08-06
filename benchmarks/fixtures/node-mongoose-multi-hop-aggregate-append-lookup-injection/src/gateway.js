import { viewAccounts } from "./service.js";

export async function routeAccountView(stages) {
  return viewAccounts(stages);
}
