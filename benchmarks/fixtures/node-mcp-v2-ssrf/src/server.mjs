import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

export const server = new McpServer({ name: "retrieval", version: "1.0.0" });

export async function loadUrl(url) {
  const response = await fetch(url, { signal: AbortSignal.timeout(2_000) });
  return response.text();
}

server.registerTool(
  "load-url",
  {
    description: "Load a URL",
    inputSchema: z.object({ url: z.string().url().max(2_048) }),
  },
  async ({ url }) => {
    const text = await loadUrl(url);
    return { content: [{ type: "text", text }] };
  },
);
