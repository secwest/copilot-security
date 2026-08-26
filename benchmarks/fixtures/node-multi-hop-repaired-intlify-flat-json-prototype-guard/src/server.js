import { routeMessages } from "./gateway.js";

export function localeEndpoint(request) {
  return routeMessages(request.body.messages);
}
