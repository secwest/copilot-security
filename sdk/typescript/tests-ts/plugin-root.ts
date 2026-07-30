import { fileURLToPath } from "node:url";

const bundledPlugin = new URL("../_bundled_plugin/", import.meta.url);

export const PLUGIN_ROOT = fileURLToPath(bundledPlugin);

export const INTEGRATION_TARGET =
  "benchmarks/fixtures/javascript-command-injection";
