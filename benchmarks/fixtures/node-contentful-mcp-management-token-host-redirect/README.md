# Contentful MCP management-token host redirect benchmark

The production entry point launches the exact declared `@contentful/mcp-server`
version. Its disabled migration tools can be enabled through the registered
workflow handler. The benchmark compares whether `export_space` and
`import_space` admit LLM-controlled management-network options or pin the CMA
host from operator configuration.

Validation must use a fake token and a random loopback-only capture endpoint.
It must never contact Contentful, use a real credential, or run a destructive
import or export against an actual space.
