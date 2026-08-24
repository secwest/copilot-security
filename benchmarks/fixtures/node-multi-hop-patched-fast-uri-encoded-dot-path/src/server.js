import { relayAsset } from "./gateway.js";

export function publishRoute(request) {
  const user = request.user;
  authorizePublisher(user);
  auditPublish(user);
  return relayAsset(request.body.assetUrl, request.body.content);
}
