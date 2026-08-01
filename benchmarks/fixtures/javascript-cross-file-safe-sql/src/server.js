import { findUserByEmail } from "./users.js";

export async function searchUsers(request, response, database) {
  const email = String(request.query.email ?? "");
  const result = await findUserByEmail(email, database);
  return response.json(result.rows);
}
