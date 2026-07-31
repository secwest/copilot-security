const TRUSTED_ORIGINS = new Set(["https://portal.example.test"]);

export function applyCredentialedCors(request, response) {
  const origin = String(request.headers.origin ?? "");
  if (!TRUSTED_ORIGINS.has(origin)) return false;
  response.setHeader("Access-Control-Allow-Origin", origin);
  response.setHeader("Access-Control-Allow-Credentials", "true");
  response.setHeader("Vary", "Origin");
  return true;
}
