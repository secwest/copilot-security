import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { Kysely, MysqlDialect } from "kysely";

const manifest = JSON.parse(
  await readFile(new URL("package.json", import.meta.url), "utf8"),
);
const version = manifest.dependencies.kysely;
const pool = {
  async end() {},
  async getConnection() {
    throw new Error("the compile-only witness must not open a database");
  },
};
const db = new Kysely({ dialect: new MysqlDialect({ pool }) });
const input = "\\' OR 1=1 --";
const compiled = db.schema
  .createIndex("orders_status_index")
  .on("orders")
  .column("status")
  .where("status", "=", input)
  .compile();
await db.destroy();

assert.deepEqual(compiled.parameters, []);
assert.equal(compiled.sql.includes("OR 1=1 --"), true);
if (version === "0.28.13") {
  assert.equal(compiled.sql.includes("= '\\'' OR 1=1 --'"), true);
} else {
  assert.equal(compiled.sql.includes("= '\\\\'' OR 1=1 --'"), true);
}
console.log(JSON.stringify({ version, input, sql: compiled.sql }));
