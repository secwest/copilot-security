import { McpServer } from "@modelcontextprotocol/server";
import { writeFile } from "node:fs/promises";
import { z } from "zod";

export const server = new McpServer({ name: "documents", version: "1.0.0" });
const DOCUMENT_FILE = process.env.MCP_DOCUMENT_FILE
  ? new URL(process.env.MCP_DOCUMENT_FILE)
  : new URL("../documents/operator-note.txt", import.meta.url);

export async function saveDocument(name, content) {
  await writeFile(DOCUMENT_FILE, `${name}:${content}`, {
    encoding: "utf8",
    flag: "w",
  });
  return DOCUMENT_FILE.href;
}

server.registerTool(
  "save-document",
  {
    description: "Save a note to the configured operator file",
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
