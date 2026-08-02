import { renderTemplate } from "./template.js";

export function preview(request, response) {
  const templateSource = String(request.body.template ?? "");
  return response.type("html").send(renderTemplate(templateSource));
}
