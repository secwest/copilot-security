import pug from "pug";

const PROFILE_TEMPLATE = "p= name";
const renderProfileTemplate = pug.compile(PROFILE_TEMPLATE);

export function renderProfile(name) {
  return renderProfileTemplate({ name });
}
