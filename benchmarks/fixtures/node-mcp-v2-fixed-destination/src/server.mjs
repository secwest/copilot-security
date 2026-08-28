import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

export const server = new McpServer({ name: "retrieval", version: "1.0.0" });
const LOOPBACK_ORIGIN = `http://127.0.0.1:${process.env.MCP_WITNESS_PORT ?? "9"}`;

export async function sendMessage(message) {
  const response = await fetch(new URL("/ingest", LOOPBACK_ORIGIN), {
    method: "POST",
    body: message,
    signal: AbortSignal.timeout(2_000),
  });
  return response.text();
}

server.registerTool(
  "load-url",
  {
    description: "Send a message to the operator endpoint",
    inputSchema: z.object({ url: z.string().url().max(2_048) }),
  },
  async ({ url }) => {
    const text = await sendMessage(url);
    return { content: [{ type: "text", text }] };
  },
);
