import { routeHostCheck } from "./gateway.js";

export function checkHost(request, response) {
  const host = String(request.query.host ?? "");
  return routeHostCheck(host, response);
}
