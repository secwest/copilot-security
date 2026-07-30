const ASSET = /^[a-z0-9][a-z0-9._-]{0,63}$/i;

export async function preview(request, response) {
  const asset = String(request.query.asset ?? "");
  if (!ASSET.test(asset)) return response.status(400).end();
  const target = new URL(
    `/previews/${encodeURIComponent(asset)}`,
    "https://assets.example.internal",
  );
  const upstream = await fetch(target, { redirect: "error" });
  return response
    .type(upstream.headers.get("content-type") ?? "text/plain")
    .send(await upstream.text());
}
