import { loadDocument } from "./service.js";

export function routeDocumentRead(key) {
  return loadDocument(key);
}
