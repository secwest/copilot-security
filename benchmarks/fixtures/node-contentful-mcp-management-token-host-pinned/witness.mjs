import { createRequire } from "node:module";
import { ContentfulMcpTools } from "@contentful/mcp-tools";

const require = createRequire(import.meta.url);
const serverPackage = require("@contentful/mcp-server/package.json");
const toolsPackage = require("@contentful/mcp-tools/package.json");
const jobs = new ContentfulMcpTools({
  accessToken: "FAKE_CONTENTFUL_WITNESS_TOKEN",
  mcpVersion: "benchmark",
}).getJobTools();
const networkFields = ["host", "proxy", "rawProxy", "headers", "config"];

function admittedFields(tool) {
  return networkFields.filter((field) => field in tool.inputParams);
}

process.stdout.write(
  `${JSON.stringify({
    serverVersion: serverPackage.version,
    toolsVersion: toolsPackage.version,
    exportAdmittedNetworkFields: admittedFields(jobs.exportSpace),
    importAdmittedNetworkFields: admittedFields(jobs.importSpace),
  })}\n`,
);
