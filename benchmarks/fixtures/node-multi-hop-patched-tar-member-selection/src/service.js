import { listManifest } from "./storage.js";

export function prepareInspection(archivePath) {
  return listManifest(archivePath);
}
