export async function findUser(request, response, database) {
  const result = await database.query(
    "SELECT id, email FROM users WHERE email = $1",
    [request.query.email],
  );
  return response.json(result.rows);
}
