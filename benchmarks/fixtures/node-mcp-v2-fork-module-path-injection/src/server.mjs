import { McpServer } from "@modelcontextprotocol/server";
import { fork } from "node:child_process";
import { z } from "zod";

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function runModule(modulePath) {
  return new Promise((resolve, reject) => {
    const child = fork(modulePath, [], { execArgv: [], silent: true });
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("The bounded fork witness timed out."));
    }, 2_000);
    child.once("message", (message) => {
      clearTimeout(timeout);
      resolve(message);
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

server.registerTool(
  "run-module",
  {
    description: "Run one fixture-local child module",
    inputSchema: z.object({ modulePath: z.string().min(1).max(512) }),
  },
  async ({ modulePath }) => {
    const output = await runModule(modulePath);
    return { content: [{ type: "text", text: JSON.stringify(output) }] };
  },
);
