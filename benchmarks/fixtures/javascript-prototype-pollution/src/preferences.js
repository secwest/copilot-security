export function updatePreference(request, response, settings) {
  const segments = String(request.body.path).split(".");
  let cursor = settings;
  for (const key of segments.slice(0, -1)) {
    cursor[key] ??= {};
    cursor = cursor[key];
  }
  const leaf = segments.at(-1);
  cursor[leaf] = request.body.value;
  return response.json({ updated: request.body.path });
}
