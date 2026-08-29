import { McpServer } from "@modelcontextprotocol/server";
import { execFile } from "node:child_process";
import { z } from "zod";

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function probeSearchPath(searchPath) {
  return new Promise((resolve) => {
    execFile(
      "node",
      ["--version"],
      {
        env: { ...process.env, PATH: searchPath },
        maxBuffer: 4_096,
        shell: false,
        timeout: 2_000,
        windowsHide: true,
      },
      (error, stdout) => {
        if (error !== null) {
          resolve({ started: false, code: error.code ?? "UNKNOWN" });
          return;
        }
        resolve({ started: true, version: stdout.trim() });
      },
    );
  });
}

server.registerTool(
  "probe-search-path",
  {
    description: "Probe a fixed command through the requested executable path",
    inputSchema: z.object({ searchPath: z.string().max(4_096) }),
  },
  async ({ searchPath }) => {
    const output = await probeSearchPath(searchPath);
    return { content: [{ type: "text", text: JSON.stringify(output) }] };
  },
);
