import { loadUser } from "./service.js";

export function routeUserLookup(id, database) {
  return loadUser(id, database);
}
