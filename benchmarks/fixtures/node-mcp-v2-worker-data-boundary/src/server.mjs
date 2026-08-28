import { McpServer } from "@modelcontextprotocol/server";
import { Worker } from "node:worker_threads";
import { z } from "zod";

export const server = new McpServer({
  name: "worker-calculator",
  version: "1.0.0",
});

const ARITHMETIC = /^\s*(-?\d+(?:\.\d+)?)\s*([+*])\s*(-?\d+(?:\.\d+)?)\s*$/u;
const WORKER_SOURCE = `
  const { parentPort, workerData } = require("node:worker_threads");
  const { left, operator, right } = workerData;
  parentPort.postMessage(operator === "+" ? left + right : left * right);
`;

export function evaluateExpression(expression) {
  const match = ARITHMETIC.exec(expression);
  if (match === null) throw new TypeError("Unsupported arithmetic expression");
  const left = Number(match[1]);
  const operator = match[2];
  const right = Number(match[3]);
  return new Promise((resolve, reject) => {
    const worker = new Worker(WORKER_SOURCE, {
      eval: true,
      workerData: { left, operator, right },
    });
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
    description: "Calculate a constrained expression in a worker",
    inputSchema: z.object({ expression: z.string().min(1).max(512) }),
  },
  async ({ expression }) => {
    const result = await evaluateExpression(expression);
    return { content: [{ type: "text", text: String(result) }] };
  },
);
