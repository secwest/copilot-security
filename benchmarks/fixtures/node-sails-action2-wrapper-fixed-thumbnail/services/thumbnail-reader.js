import fs from "node:fs";
import path from "node:path";

export function readThumbnail(_filename) {
  const filePath = path.join(
    import.meta.dirname,
    "../data/thumbnails",
    "cover-256.jpg",
  );
  return fs.readFileSync(filePath, "utf8");
}
