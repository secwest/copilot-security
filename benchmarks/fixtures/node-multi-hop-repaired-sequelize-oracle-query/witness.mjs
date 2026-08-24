import { createRequire } from "node:module";
import { readFile } from "node:fs/promises";

const require = createRequire(import.meta.url);
const { DataTypes, Sequelize } = require("sequelize");
const metadata = JSON.parse(
  await readFile(
    new URL("./node_modules/sequelize/package.json", import.meta.url),
    "utf8",
  ),
);
const oracleModule = new Proxy(
  { CLOB: 1, BLOB: 2 },
  { get: (target, key) => target[key] ?? 0 },
);
const sequelize = new Sequelize("students", "application", "password", {
  dialect: "oracle",
  dialectModule: oracleModule,
  logging: false,
});
const Student = sequelize.define(
  "Student",
  { firstName: DataTypes.STRING },
  { tableName: "Students", timestamps: false },
);
const payload = "TO_DATE('0','Y')||'' OR 1=1--";

let query = null;
let error = null;
try {
  query = sequelize.dialect.queryGenerator.selectQuery(
    Student.getTableName(),
    { where: { firstName: payload }, model: Student },
    Student,
  );
} catch (caught) {
  error = caught instanceof Error ? caught.message : String(caught);
}

const vulnerable = metadata.version === "6.37.3";
const injected = query?.includes("OR 1=1--") === true;
const rejected = error === "Invalid SQL function call.";
if ((vulnerable && !injected) || (!vulnerable && !rejected)) {
  throw new Error(
    `Unexpected Sequelize Oracle boundary for ${metadata.version}: query=${query}, error=${error}`,
  );
}
console.log(
  JSON.stringify({ version: metadata.version, injected, query, error }),
);
