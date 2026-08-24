import { Liquid } from "liquidjs";

const engine = new Liquid();

export function renderDocument(template) {
  return engine.parseAndRender(template, {});
}
