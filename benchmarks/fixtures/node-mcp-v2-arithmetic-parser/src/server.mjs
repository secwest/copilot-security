import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

export const server = new McpServer({ name: "calculator", version: "1.0.0" });

const ARITHMETIC = /^\s*(-?\d+(?:\.\d+)?)\s*([+*])\s*(-?\d+(?:\.\d+)?)\s*$/u;

export function evaluateExpression(expression) {
  const match = ARITHMETIC.exec(expression);
  if (match === null) throw new TypeError("Unsupported arithmetic expression");
  const left = Number(match[1]);
  const right = Number(match[3]);
  return match[2] === "+" ? left + right : left * right;
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
