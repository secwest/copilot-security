import { routeDocumentRead } from "./gateway.js";

export function getDocument(request) {
  const name = String(request.query.path ?? "");
  return routeDocumentRead(name);
}
