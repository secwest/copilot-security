import { McpServer } from "@modelcontextprotocol/server";
import { fork } from "node:child_process";
import { z } from "zod";

const childModule = new URL("./child.mjs", import.meta.url);

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function runWithNodeOptions(nodeOptions) {
  return new Promise((resolve, reject) => {
    const child = fork(childModule, [], {
      env: { ...process.env, NODE_OPTIONS: nodeOptions },
      execArgv: [],
      silent: true,
    });
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("The bounded NODE_OPTIONS fork witness timed out."));
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
  "run-with-node-options",
  {
    description: "Run a fixed child with requested Node runtime options",
    inputSchema: z.object({ nodeOptions: z.string().min(1).max(512) }),
  },
  async ({ nodeOptions }) => {
    const output = await runWithNodeOptions(nodeOptions);
    return { content: [{ type: "text", text: JSON.stringify(output) }] };
  },
);
