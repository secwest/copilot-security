const HTML_ESCAPES = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

function escapeHtml(value) {
  return value.replace(/[&<>"']/g, (character) => HTML_ESCAPES[character]);
}

export function welcome(request, response) {
  const name = escapeHtml(String(request.query.name ?? ""));
  return response.type("html").send(`<h1>Welcome, ${name}</h1>`);
}
