import { loadUser } from "./service.js";

export async function findUser(request, response, database) {
  const id = String(request.query.id ?? "");
  const result = await loadUser(id, database);
  return response.json(result.rows);
}
