import { routeDocumentRead } from "./gateway.js";

export function getDocument(request) {
  const key = String(request.query.path ?? "");
  return routeDocumentRead(key);
}
