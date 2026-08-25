import { routeStatusIndex } from "./gateway.js";

export function statusIndexEndpoint(request) {
  return routeStatusIndex(request.query.status);
}
