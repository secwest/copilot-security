import * as tar from "tar";

export function unpackArchive(archivePath) {
  return tar.x({ file: archivePath, cwd: "/srv/imports" });
}
