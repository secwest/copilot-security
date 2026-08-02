import { dispatchHostCheck } from "./service.js";

export function checkHost(request, response) {
  const host = String(request.query.host ?? "");
  return dispatchHostCheck(host, response);
}
