export function welcome(request, response) {
  const name = String(request.query.name ?? "");
  return response.type("html").send(`<h1>Welcome, ${name}</h1>`);
}
