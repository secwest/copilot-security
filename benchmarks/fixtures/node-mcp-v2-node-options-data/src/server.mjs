import { McpServer } from "@modelcontextprotocol/server";
import { spawn } from "node:child_process";
import { execPath } from "node:process";
import { fileURLToPath } from "node:url";
import { z } from "zod";

const childModule = fileURLToPath(new URL("./child.mjs", import.meta.url));

export const server = new McpServer({ name: "diagnostics", version: "1.0.0" });

export function runWithEnvironmentData(nodeOptions) {
  return new Promise((resolve, reject) => {
    const child = spawn(execPath, [childModule], {
      env: {
        ...process.env,
        NODE_OPTIONS: "",
        COPILOT_SECURITY_NODE_OPTIONS_DATA: nodeOptions,
      },
      shell: false,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timeout = setTimeout(() => {
      child.kill();
      reject(new Error("The bounded process environment control timed out."));
    }, 2_000);
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout = `${stdout}${chunk}`;
      if (stdout.length > 4_096) child.kill();
    });
    child.stderr.on("data", (chunk) => {
      stderr = `${stderr}${chunk}`;
      if (stderr.length > 4_096) child.kill();
    });
    child.once("error", (error) => {
      clearTimeout(timeout);
      reject(error);
    });
    child.once("close", (code) => {
      clearTimeout(timeout);
      if (code !== 0) {
        reject(new Error(`The fixed Node child failed: ${stderr.trim()}`));
        return;
      }
      resolve(JSON.parse(stdout));
    });
  });
}

server.registerTool(
  "run-with-environment-data",
  {
    description: "Pass option-looking text as ordinary process environment data",
    inputSchema: z.object({ nodeOptions: z.string().min(1).max(512) }),
  },
  async ({ nodeOptions }) => {
    const output = await runWithEnvironmentData(nodeOptions);
    return { content: [{ type: "text", text: JSON.stringify(output) }] };
  },
);
