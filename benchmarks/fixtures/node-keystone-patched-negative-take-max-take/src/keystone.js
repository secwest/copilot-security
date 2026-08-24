import { config } from "@keystone-6/core";
import { lists } from "./schema.js";

export default config({
  db: { provider: "sqlite", url: "file:./benchmark.db" },
  lists,
});
