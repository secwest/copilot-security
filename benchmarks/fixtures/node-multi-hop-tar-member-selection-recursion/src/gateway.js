import { prepareInspection } from "./service.js";

export function inspectTar(archivePath) {
  return prepareInspection(archivePath);
}
