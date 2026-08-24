import * as tar from "tar";

export function listManifest(archivePath) {
  return tar.t({ file: archivePath, gzip: true }, ["manifest.json"]);
}
