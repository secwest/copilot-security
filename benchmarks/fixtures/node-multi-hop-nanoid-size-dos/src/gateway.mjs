import { createPublicId } from "./service.mjs";

export function routeId(size) {
  return createPublicId(size);
}
