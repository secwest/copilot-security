import { runHostCheck } from "./runner.js";

export function checkHost(request, response) {
  const host = String(request.query.host ?? "");
  return runHostCheck(host, response);
}
