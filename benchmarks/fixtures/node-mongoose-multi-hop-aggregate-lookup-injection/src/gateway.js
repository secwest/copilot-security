import { buildAccountReport } from "./service.js";

export async function routeAccountReport(pipeline) {
  return buildAccountReport(pipeline);
}
