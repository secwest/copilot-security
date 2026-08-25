import { Kysely, MysqlDialect } from "kysely";

const pool = {
  async end() {},
  async getConnection() {
    throw new Error("compile-only fixture");
  },
};
const db = new Kysely({ dialect: new MysqlDialect({ pool }) });

export function compileStatusIndex(status) {
  return db.schema
    .createIndex("orders_status_index")
    .on("orders")
    .column("status")
    .where("status", "=", status)
    .compile();
}
