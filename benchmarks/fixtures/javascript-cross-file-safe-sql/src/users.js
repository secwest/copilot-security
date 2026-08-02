export async function findUserByEmail(email, database) {
  return database.query("SELECT 1 WHERE value = $1", [email]);
}
