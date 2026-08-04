import { fetchPreview } from "./upstream.js";

export function preview(request, response) {
  const target = String(request.query.url ?? "");
  return fetchPreview(target, response);
}
