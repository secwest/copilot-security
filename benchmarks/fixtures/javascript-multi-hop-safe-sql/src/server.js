import { routeUserLookup } from "./gateway.js";

export async function findUser(request, response, database) {
  const id = String(request.query.id ?? "");
  const result = await routeUserLookup(id, database);
  return response.json(result.rows);
}
