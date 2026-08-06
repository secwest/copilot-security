import { loadDocument } from "./service.js";

export function routeDocumentRead(name) {
  return loadDocument(name);
}
