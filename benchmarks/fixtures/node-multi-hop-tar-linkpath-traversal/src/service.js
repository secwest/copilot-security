import { unpackArchive } from "./storage.js";

export function prepareImport(archivePath) {
  return unpackArchive(archivePath);
}
