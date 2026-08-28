import { StdioServerTransport } from "@modelcontextprotocol/server/stdio";
import { server } from "./server.mjs";

await server.connect(new StdioServerTransport());
