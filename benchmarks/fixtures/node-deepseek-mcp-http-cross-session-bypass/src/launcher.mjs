process.env.TRANSPORT = "http";
process.env.SKIP_CONNECTION_TEST = "true";
await import("@arikusi/deepseek-mcp-server");
