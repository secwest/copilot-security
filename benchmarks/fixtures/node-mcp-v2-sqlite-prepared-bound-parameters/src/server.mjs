import { McpServer } from "@modelcontextprotocol/server";
import { DatabaseSync } from "node:sqlite";
import { z } from "zod";

const database = new DatabaseSync(":memory:");
database.exec("CREATE TABLE accounts (name TEXT NOT NULL, role TEXT NOT NULL)");
database.exec(
  "INSERT INTO accounts VALUES ('public', 'viewer'), ('service-owner', 'admin')",
);

export const server = new McpServer({
  name: "prepared-account-lookup",
  version: "1.0.0",
});

export function lookupRole(name) {
  const statement = database.prepare(
    "SELECT role FROM accounts WHERE name = ? ORDER BY role",
  );
  return statement.get(name)?.role ?? null;
}

server.registerTool(
  "lookup-role",
  {
    description: "Look up one account role",
    inputSchema: z.object({ name: z.string().min(1).max(256) }),
  },
  async ({ name }) => {
    const role = lookupRole(name);
    return { content: [{ type: "text", text: role ?? "not found" }] };
  },
);
