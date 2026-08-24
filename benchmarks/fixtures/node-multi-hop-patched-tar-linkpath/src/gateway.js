import { prepareImport } from "./service.js";

export function receiveTar(archivePath) {
  return prepareImport(archivePath);
}
