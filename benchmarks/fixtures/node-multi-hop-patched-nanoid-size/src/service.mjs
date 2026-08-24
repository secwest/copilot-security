import { issueId } from "./storage.mjs";

export function createPublicId(size) {
  return issueId(size);
}
