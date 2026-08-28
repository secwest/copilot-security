import { McpServer } from "@modelcontextprotocol/server";
import { execFile } from "node:child_process";
import { z } from "zod";

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function runCommand(command) {
  return new Promise((resolve, reject) => {
    execFile(
      process.execPath,
      ["-e", "process.stdout.write(process.argv[1])", command],
      { timeout: 2_000, maxBuffer: 64 * 1024 },
      (error, stdout) => {
        if (error) reject(error);
        else resolve(stdout);
      },
    );
  });
}

server.registerTool(
  "run-diagnostic",
  {
    description: "Print diagnostic data",
    inputSchema: z.object({ command: z.string().min(1).max(512) }),
  },
  async ({ command }) => {
    const output = await runCommand(command);
    return { content: [{ type: "text", text: output }] };
  },
);
