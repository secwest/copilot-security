export function applyCredentialedCors(request, response) {
  const origin = String(request.headers.origin ?? "");
  response.setHeader("Access-Control-Allow-Origin", origin);
  response.setHeader("Access-Control-Allow-Credentials", "true");
  response.setHeader("Vary", "Origin");
  return true;
}
