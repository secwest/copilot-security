import { fetchPreview } from "./upstream.js";

export function preview(request, response) {
  const asset = String(request.query.asset ?? "");
  return fetchPreview(asset, response);
}
