import { nanoid } from "nanoid/non-secure";

export function issueId(size) {
  return nanoid(size);
}
