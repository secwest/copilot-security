import pug from "pug";

export function renderTemplate(templateSource) {
  const render = pug.compile(templateSource);
  return render({ siteName: "Preview" });
}
