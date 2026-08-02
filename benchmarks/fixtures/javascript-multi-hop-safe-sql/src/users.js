export function queryUser(id, database) {
  return database.query("SELECT id FROM users WHERE id = $1", [id]);
}
