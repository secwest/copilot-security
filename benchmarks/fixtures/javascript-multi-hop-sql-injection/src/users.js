export function queryUser(id, database) {
  return database.query(`SELECT id FROM users WHERE id = '${id}'`);
}
