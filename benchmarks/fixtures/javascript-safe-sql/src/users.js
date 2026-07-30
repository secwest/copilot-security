export async function searchUsers(request, response, database) {
  const email = String(request.query.email ?? "");
  const result = await database.query(
    "SELECT id, email FROM users WHERE email = $1",
    [email],
  );
  return response.json(result.rows);
}
