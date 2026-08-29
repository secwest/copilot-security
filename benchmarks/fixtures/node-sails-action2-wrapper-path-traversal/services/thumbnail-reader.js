import fs from "node:fs";
import path from "node:path";

export function readThumbnail(filename) {
  const filePath = path.join(
    import.meta.dirname,
    "../data/thumbnails",
    filename,
  );
  return fs.readFileSync(filePath, "utf8");
}
