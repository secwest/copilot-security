import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

export const server = new McpServer({ name: "calculator", version: "1.0.0" });

export function evaluateExpression(expression) {
  return eval(expression);
}

server.registerTool(
  "calculate-expression",
  {
    description: "Calculate an expression",
    inputSchema: z.object({ expression: z.string().min(1).max(256) }),
  },
  async ({ expression }) => {
    const result = evaluateExpression(expression);
    return { content: [{ type: "text", text: String(result) }] };
  },
);
