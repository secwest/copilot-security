const ALLOWED_PREFERENCES = new Set(["locale", "theme"]);

export function updatePreference(request, response, settings) {
  const key = String(request.body.key);
  if (!ALLOWED_PREFERENCES.has(key)) return response.status(400).end();
  settings.set(key, request.body.value);
  return response.json({ updated: key });
}
