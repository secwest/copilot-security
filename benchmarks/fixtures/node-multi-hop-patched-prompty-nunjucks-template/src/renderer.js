import { NunjucksRenderer } from "@prompty/core";

const renderer = new NunjucksRenderer();

export function renderDocument(template) {
  return renderer.render({}, template, {});
}
