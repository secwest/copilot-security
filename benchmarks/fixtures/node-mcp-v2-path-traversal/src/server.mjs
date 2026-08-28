import { McpServer } from "@modelcontextprotocol/server";
import { writeFile } from "node:fs/promises";
import { z } from "zod";

export const server = new McpServer({ name: "documents", version: "1.0.0" });
const DOCUMENT_ROOT = process.env.MCP_DOCUMENT_ROOT
  ? new URL(process.env.MCP_DOCUMENT_ROOT)
  : new URL("../documents/", import.meta.url);

export async function saveDocument(name, content) {
  const target = new URL(name, DOCUMENT_ROOT);
  await writeFile(target, content, { encoding: "utf8", flag: "w" });
  return target.href;
}

server.registerTool(
  "save-document",
  {
    description: "Save a document under the configured document directory",
    inputSchema: z.object({
      name: z.string().min(1).max(256),
      content: z.string().max(16_384),
    }),
  },
  async ({ name, content }) => {
    const location = await saveDocument(name, content);
    return { content: [{ type: "text", text: location }] };
  },
);
