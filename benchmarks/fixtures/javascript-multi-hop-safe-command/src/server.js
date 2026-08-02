import { dispatchHostCheck } from "./service.js";

const ALLOWED_CHECKS = new Set(["status"]);

export function checkHost(request, response) {
  const host = String(request.query.host ?? "");
  if (!ALLOWED_CHECKS.has(host)) return response.status(400).end();
  return dispatchHostCheck(host, response);
}
