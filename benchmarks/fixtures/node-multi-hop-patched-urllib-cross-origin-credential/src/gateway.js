import { forwardPartnerCredential } from "./service.js";

export function routePartnerRequest(authorization) {
  return forwardPartnerCredential(authorization);
}
