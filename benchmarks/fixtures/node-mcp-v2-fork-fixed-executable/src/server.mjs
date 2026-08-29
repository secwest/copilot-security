import { McpServer } from "@modelcontextprotocol/server";
import { fork } from "node:child_process";
import { z } from "zod";

const childModule = new URL("./child.mjs", import.meta.url);

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function runWithExecutable(execPath) {
  return new Promise((resolve, reject) => {
    const child = fork(childModule, [execPath], {
      execPath: process.execPath,
      execArgv: [],
      silent: true,
    });
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("The bounded fork control timed out."));
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
  "run-executable",
  {
    description: "Pass an executable-looking value to a fixed child",
    inputSchema: z.object({ execPath: z.string().min(1).max(512) }),
  },
  async ({ execPath }) => {
    const output = await runWithExecutable(execPath);
    return { content: [{ type: "text", text: JSON.stringify(output) }] };
  },
);
