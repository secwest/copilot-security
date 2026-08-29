import { McpServer } from "@modelcontextprotocol/server";
import { execFile } from "node:child_process";
import { dirname } from "node:path";
import { execPath } from "node:process";
import { z } from "zod";

const fixedSearchPath = dirname(execPath);

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function probeFixedSearchPath(searchPath) {
  return new Promise((resolve) => {
    execFile(
      "node",
      ["--version"],
      {
        env: {
          ...process.env,
          PATH: fixedSearchPath,
          COPILOT_SECURITY_PATH_DATA: searchPath,
        },
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
  "probe-fixed-search-path",
  {
    description: "Pass path-looking text as ordinary process environment data",
    inputSchema: z.object({ searchPath: z.string().max(4_096) }),
  },
  async ({ searchPath }) => {
    const output = await probeFixedSearchPath(searchPath);
    return { content: [{ type: "text", text: JSON.stringify(output) }] };
  },
);
