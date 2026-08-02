import { renderProfile } from "./template.js";

export function preview(request, response) {
  const name = String(request.body.name ?? "");
  return response.type("html").send(renderProfile(name));
}
