import { fetchPreview } from "./upstream.js";

export async function preview(request, response) {
  const body = await fetchPreview(request.query.url);
  return response.send(body);
}
