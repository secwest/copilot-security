import { storeAsset } from "./storage.js";

export function prepareAsset(assetUrl, content) {
  return storeAsset(assetUrl, content);
}
