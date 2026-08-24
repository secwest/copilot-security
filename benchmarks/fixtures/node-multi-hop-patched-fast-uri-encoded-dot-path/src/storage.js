import fastUri from "fast-uri";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";

const PUBLIC_URL = "https://assets.example/public/";
const ASSET_ROOT = "asset-store";

export async function storeAsset(assetUrl, content) {
  if (!assetUrl.startsWith(PUBLIC_URL)) throw new Error("private asset path");
  return writeFile(
    join(ASSET_ROOT, fastUri.parse(fastUri.normalize(assetUrl)).path.slice(1)),
    content,
  );
}
