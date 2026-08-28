import { McpServer } from "@modelcontextprotocol/server";
import { exec } from "node:child_process";
import { z } from "zod";

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function runCommand(command) {
  return new Promise((resolve, reject) => {
    exec(command, { timeout: 2_000, maxBuffer: 64 * 1024 }, (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout);
    });
  });
}

server.registerTool(
  "run-diagnostic",
  {
    description: "Run a diagnostic command",
    inputSchema: z.object({ command: z.string().min(1).max(512) }),
  },
  async ({ command }) => {
    const output = await runCommand(command);
    return { content: [{ type: "text", text: output }] };
  },
);
