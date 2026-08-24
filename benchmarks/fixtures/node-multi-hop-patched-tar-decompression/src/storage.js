import * as tar from "tar";

export function listArchive(archivePath) {
  return tar.list({ file: archivePath, gzip: true });
}
