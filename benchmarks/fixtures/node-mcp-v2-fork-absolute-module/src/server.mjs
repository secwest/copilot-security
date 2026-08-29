import { McpServer } from "@modelcontextprotocol/server";
import { fork } from "node:child_process";
import { z } from "zod";

const childModule = new URL("./child.mjs", import.meta.url);

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function runFromDirectory(cwd) {
  return new Promise((resolve, reject) => {
    const child = fork(childModule, [], { cwd, execArgv: [], silent: true });
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("The bounded absolute-module fork control timed out."));
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
  "run-from-directory",
  {
    description: "Run one fixed child while preserving directory input",
    inputSchema: z.object({ cwd: z.string().min(1).max(512) }),
  },
  async ({ cwd }) => {
    const output = await runFromDirectory(cwd);
    return { content: [{ type: "text", text: JSON.stringify(output) }] };
  },
);
