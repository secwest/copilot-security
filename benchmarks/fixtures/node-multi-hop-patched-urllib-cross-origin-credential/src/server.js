import { routePartnerRequest } from "./gateway.js";

export function partnerEndpoint(request) {
  return routePartnerRequest(request.headers.authorization);
}
