import { McpServer } from "@modelcontextprotocol/server";
import { fork } from "node:child_process";
import { z } from "zod";

const childModule = new URL("./child.mjs", import.meta.url);

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function runWithEnvironmentData(nodeOptions) {
  return new Promise((resolve, reject) => {
    const child = fork(childModule, [], {
      env: { ...process.env, COPILOT_SECURITY_NODE_OPTIONS_DATA: nodeOptions },
      execArgv: [],
      silent: true,
    });
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("The bounded fork environment control timed out."));
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
  "run-with-environment-data",
  {
    description: "Pass option-looking text as ordinary child environment data",
    inputSchema: z.object({ nodeOptions: z.string().min(1).max(512) }),
  },
  async ({ nodeOptions }) => {
    const output = await runWithEnvironmentData(nodeOptions);
    return { content: [{ type: "text", text: JSON.stringify(output) }] };
  },
);
