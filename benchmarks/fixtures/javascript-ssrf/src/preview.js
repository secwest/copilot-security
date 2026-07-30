export async function preview(request, response) {
  const target = String(request.query.url ?? "");
  const upstream = await fetch(target, { redirect: "follow" });
  return response
    .type(upstream.headers.get("content-type") ?? "text/plain")
    .send(await upstream.text());
}
