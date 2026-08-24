import { listArchive } from "./storage.js";

export function inspectArchive(archivePath) {
  return listArchive(archivePath);
}
