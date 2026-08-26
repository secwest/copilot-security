import { requestPartner } from "./storage.js";

export function forwardPartnerCredential(authorization) {
  return requestPartner(authorization);
}
