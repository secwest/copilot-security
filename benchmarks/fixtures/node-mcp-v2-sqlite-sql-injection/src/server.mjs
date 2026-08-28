import { McpServer } from "@modelcontextprotocol/server";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";

const database = new DatabaseSync(":memory:");
database.exec("CREATE TABLE audit (term TEXT NOT NULL)");

export const server = new McpServer({
  name: "sqlite-audit",
  version: "1.0.0",
});

export function resetAudit() {
  database.exec("DELETE FROM audit");
}

export function recordLookup(term) {
  const sql = `INSERT INTO audit (term) VALUES ('${term}')`;
  database.exec(sql);
  return database.prepare("SELECT COUNT(*) AS count FROM audit").get().count;
}

export function recordedTerms() {
  return database.prepare("SELECT term FROM audit ORDER BY rowid").all();
}

server.registerTool(
  "record-lookup",
  {
    description: "Record an audited lookup term",
    inputSchema: z.object({ term: z.string().min(1).max(256) }),
  },
  async ({ term }) => {
    const count = recordLookup(term);
    return { content: [{ type: "text", text: String(count) }] };
  },
);
