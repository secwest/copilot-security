import { McpServer } from "@modelcontextprotocol/server";
import { Worker } from "node:worker_threads";
import { z } from "zod";

export const server = new McpServer({
  name: "worker-calculator",
  version: "1.0.0",
});

export function evaluateExpression(expression) {
  return new Promise((resolve, reject) => {
    const worker = new Worker(expression, { eval: true });
    worker.once("message", resolve);
    worker.once("error", reject);
    worker.once("exit", (code) => {
      if (code !== 0)
        reject(new Error(`Worker stopped with exit code ${code}`));
    });
  });
}

server.registerTool(
  "calculate-expression",
  {
    description: "Calculate an expression in a worker",
    inputSchema: z.object({ expression: z.string().min(1).max(512) }),
  },
  async ({ expression }) => {
    const result = await evaluateExpression(expression);
    return { content: [{ type: "text", text: String(result) }] };
  },
);
