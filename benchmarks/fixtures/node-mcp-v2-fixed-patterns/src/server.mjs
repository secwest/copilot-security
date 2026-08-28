import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });
const PATTERNS = new Map([
  ["errors", /^error:/u],
  ["warnings", /^warning:/u],
]);

export function searchText(pattern, text) {
  const expression = PATTERNS.get(pattern);
  if (expression === undefined) return false;
  return expression.test(text);
}

server.registerTool(
  "search-diagnostics",
  {
    description: "Search diagnostic lines",
    inputSchema: z.object({
      pattern: z.string().min(1).max(64),
      text: z.string().max(4096),
    }),
  },
  async ({ pattern, text }) => {
    const matched = searchText(pattern, text);
    return {
      content: [{ type: "text", text: JSON.stringify({ matched }) }],
    };
  },
);
