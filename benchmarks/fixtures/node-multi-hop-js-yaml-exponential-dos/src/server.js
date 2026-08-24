import { parseDocument } from "./gateway.js";

export function parseRoute(request) {
  const user = request.user;
  authorizeParsing(user);
  auditParsing(user);
  return parseDocument(request.body.yaml);
}
