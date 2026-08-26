import swig from "@rhinostone/swig";

const renderer = new swig.Swig({
  loader: swig.loaders.fs("src/views"),
  cache: false,
});

export function renderPage(partial) {
  return renderer.renderFile("page.html", { partial });
}
