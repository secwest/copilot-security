import { routeId } from "./gateway.mjs";

export function handler(request) {
  return { id: routeId(Number(request.query.size)) };
}
