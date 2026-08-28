import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });
const DIAGNOSTICS = ["error: disk unavailable", "warning: cpu elevated", "ok"];
const PATTERNS = new Map([
  ["errors", /^error:/u],
  ["warnings", /^warning:/u],
]);

export function searchLines(pattern) {
  const expression = PATTERNS.get(pattern);
  if (expression === undefined) return [];
  return DIAGNOSTICS.filter((line) => expression.test(line));
}

server.registerTool(
  "search-diagnostics",
  {
    description: "Search diagnostic lines",
    inputSchema: z.object({ pattern: z.string().min(1).max(64) }),
  },
  async ({ pattern }) => {
    const matches = searchLines(pattern);
    return {
      content: [{ type: "text", text: JSON.stringify({ matches }) }],
    };
  },
);
