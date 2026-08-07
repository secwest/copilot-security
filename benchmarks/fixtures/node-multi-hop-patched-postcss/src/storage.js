import postcss from "postcss";

export async function compileStyle(css) {
  const options = { from: "/srv/styles/input.css" };
  const result = await postcss([]).process(css, options);
  return { css: result.css, map: result.map?.toString() };
}
