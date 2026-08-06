import { aggregateAccounts } from "./storage.js";

export async function buildAccountReport(pipeline) {
  return aggregateAccounts(pipeline);
}
