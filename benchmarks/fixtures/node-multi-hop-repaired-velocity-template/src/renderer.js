import { render } from "velocityjs";

export function renderDocument(template) {
  return render(template, { x: {} });
}
