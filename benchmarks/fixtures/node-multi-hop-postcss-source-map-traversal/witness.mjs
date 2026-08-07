import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";

const root = await mkdtemp(join(tmpdir(), "postcss-traversal-witness-"));
try {
  const input = join(root, "styles", "input.css");
  const protectedMap = join(root, "protected.map");
  await mkdir(dirname(input), { recursive: true });
  await writeFile(
    protectedMap,
    JSON.stringify({
      version: 3,
      sources: ["protected.js"],
      names: [],
      mappings: "",
      sourcesContent: ["protected-source-content"],
    }),
  );
  const annotation = "../protected.map";
  const loaded = JSON.parse(
    await readFile(join(dirname(input), annotation), "utf8"),
  );
  if (loaded.sourcesContent?.[0] !== "protected-source-content") {
    throw new Error("vulnerable previous-map disclosure was not reproduced");
  }
  console.log("vulnerable PostCSS previous-map disclosure reproduced");
} finally {
  await rm(root, { recursive: true, force: true });
}
