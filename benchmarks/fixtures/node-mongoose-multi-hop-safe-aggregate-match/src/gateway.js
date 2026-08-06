import { buildAccountReport } from "./service.js";

export async function routeAccountReport(criteria) {
  return buildAccountReport(criteria);
}
