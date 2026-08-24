import { relayRequest } from "./gateway.js";

export function previewRoute(request) {
  const user = request.user;
  authorizePreview(user);
  auditPreview(user);
  return relayRequest(request.query.url);
}
