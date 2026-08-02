import { queryUser } from "./users.js";

export function loadUser(id, database) {
  return queryUser(id, database);
}
