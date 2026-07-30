import { rm } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { expect, test } from "bun:test";
import { CopilotSecurity } from "../src/index.js";
import { INTEGRATION_TARGET } from "./plugin-root.js";

const REPOSITORY_ROOT = fileURLToPath(new URL("../../..", import.meta.url));

if (process.env["COPILOT_SECURITY_INTEGRATION"] === "1") {
  test(
    "real Copilot and unchanged-plugin integration smoke",
    async () => {
      const client = new CopilotSecurity();
      let scanDir: string | null = null;
      try {
        const result = await client.run(REPOSITORY_ROOT, {
          target: [INTEGRATION_TARGET],
          onOutputDirReady: (path) => {
            scanDir = path;
          },
        });
        expect(result.manifest.scan.status).toBe("completed");
      } finally {
        await client.close();
        if (scanDir !== null)
          await rm(scanDir, { recursive: true, force: true });
      }
    },
    { timeout: 10 * 60_000 },
  );
} else {
  test.skip("real Copilot and unchanged-plugin integration smoke", () => {});
}
