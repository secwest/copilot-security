import { dispatchHostCheck } from "./service.js";

export function routeHostCheck(host, response) {
  return dispatchHostCheck(host, response);
}
