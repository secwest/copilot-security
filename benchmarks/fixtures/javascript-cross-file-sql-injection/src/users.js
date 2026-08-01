export async function findUserByEmail(email, database) {
  return database.query(`SELECT id, email FROM users WHERE email = '${email}'`);
}
