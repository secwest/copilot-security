import { McpServer } from "@modelcontextprotocol/server";
import { fork } from "node:child_process";
import { z } from "zod";

const childModule = new URL("./child.mjs", import.meta.url);

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function runDiagnostic(option) {
  return new Promise((resolve, reject) => {
    const child = fork(childModule, [option], {
      execArgv: [],
      silent: true,
    });
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
  "run-diagnostic",
  {
    description: "Run a bounded child diagnostic",
    inputSchema: z.object({ option: z.string().min(1).max(64) }),
  },
  async ({ option }) => {
    const output = await runDiagnostic(option);
    return { content: [{ type: "text", text: JSON.stringify(output) }] };
  },
);
