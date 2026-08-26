import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface UndiciRecord {
  path: string;
  line: number;
  frameworkModel?: {
    id: string;
    source: { line: number };
    sink: { line: number; cweIds: string[]; kind: string };
    propagators: Array<{ kind: string; symbol?: string }>;
  };
}

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

function records(inventory: string): UndiciRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as UndiciRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "node-undici-socks5-cross-origin-routing",
    );
}

async function scan(
  source: string,
  version = "7.27.2",
  section: "dependencies" | "devDependencies" = "dependencies",
): Promise<UndiciRecord[]> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-undici-socks5-"));
  temporaryPaths.push(root);
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({
      name: "undici-socks5-case",
      private: true,
      [section]: { undici: version },
    }),
  );
  await writeFile(join(root, "server.js"), source);
  return records(await buildResidualRiskInventory(root));
}

const positive = `import { Socks5ProxyAgent, request } from "undici";
const proxy = new Socks5ProxyAgent("socks5://127.0.0.1:1080");
export async function forward(req) {
  await request(req.query.target, { dispatcher: proxy });
  return request("https://billing.internal/account", {
    dispatcher: proxy,
    headers: { authorization: process.env.BILLING_TOKEN },
  });
}
`;

describe("Undici SOCKS5 cross-origin routing model", () => {
  test("binds a remote first origin to a later credentialed origin", async () => {
    const found = await scan(positive);
    expect(found).toHaveLength(1);
    expect(found[0]?.line).toBe(5);
    expect(found[0]?.frameworkModel?.source.line).toBe(4);
    expect(found[0]?.frameworkModel?.sink.cweIds).toEqual(["CWE-346"]);
    expect(found[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "undici@7.27.2:manifest-exact:single-cross-origin-socks5-pool",
    );
  });

  test("enforces both affected release windows", async () => {
    expect(await scan(positive, "7.22.0")).toHaveLength(0);
    expect(await scan(positive, "7.23.0")).toHaveLength(1);
    expect(await scan(positive, "7.27.9")).toHaveLength(1);
    expect(await scan(positive, "7.28.0")).toHaveLength(0);
    expect(await scan(positive, "8.0.0")).toHaveLength(1);
    expect(await scan(positive, "8.1.9")).toHaveLength(1);
    expect(await scan(positive, "8.2.0")).toHaveLength(0);
    expect(await scan(positive, "8.2.0-beta.1")).toHaveLength(0);
  });

  test("supports aliased, namespace, and CommonJS bindings", async () => {
    const aliased = positive
      .replace(
        "Socks5ProxyAgent, request",
        "Socks5ProxyAgent as Agent, request as send",
      )
      .replace("new Socks5ProxyAgent", "new Agent")
      .replaceAll("request(", "send(");
    expect(await scan(aliased)).toHaveLength(1);
    const namespace = positive
      .replace(
        'import { Socks5ProxyAgent, request } from "undici";',
        'import * as net from "undici";',
      )
      .replace("new Socks5ProxyAgent", "new net.Socks5ProxyAgent")
      .replaceAll("request(", "net.request(");
    expect(await scan(namespace)).toHaveLength(1);
    const commonjs = positive.replace(
      'import { Socks5ProxyAgent, request } from "undici";',
      'const { Socks5ProxyAgent, request } = require("undici");',
    );
    expect(await scan(commonjs)).toHaveLength(1);
  });

  test("supports one official global dispatcher with no per-call override", async () => {
    const global = positive
      .replace(
        "Socks5ProxyAgent, request",
        "Socks5ProxyAgent, request, setGlobalDispatcher",
      )
      .replace(
        'const proxy = new Socks5ProxyAgent("socks5://127.0.0.1:1080");',
        'const proxy = new Socks5ProxyAgent("socks5://127.0.0.1:1080");\nsetGlobalDispatcher(proxy);',
      )
      .replace("{ dispatcher: proxy }", "{}")
      .replace("    dispatcher: proxy,\n", "");
    const found = await scan(global);
    expect(found).toHaveLength(1);
    expect(
      found[0]?.frameworkModel?.propagators.some(
        (item) => item.kind === "undici-global-dispatcher-activation",
      ),
    ).toBe(true);
    expect(
      await scan(
        global.replace(
          "setGlobalDispatcher(proxy)",
          "setGlobalDispatcher(other)",
        ),
      ),
    ).toHaveLength(0);
  });

  test("accepts only declaration-consistent modern lock proof for ranges", async () => {
    const root = await mkdtemp(join(tmpdir(), "copilot-security-undici-lock-"));
    temporaryPaths.push(root);
    await writeFile(
      join(root, "package.json"),
      JSON.stringify({
        name: "locked-undici",
        private: true,
        dependencies: { undici: "^7.23.0" },
      }),
    );
    await writeFile(
      join(root, "package-lock.json"),
      JSON.stringify({
        name: "locked-undici",
        lockfileVersion: 3,
        packages: {
          "": { name: "locked-undici", dependencies: { undici: "^7.23.0" } },
          "node_modules/undici": { version: "7.27.2" },
        },
      }),
    );
    await writeFile(join(root, "server.js"), positive);
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "lock-resolved-credentialed-later-socks5-origin",
    );
    await writeFile(
      join(root, "package-lock.json"),
      JSON.stringify({
        name: "locked-undici",
        lockfileVersion: 3,
        packages: {
          "": { name: "locked-undici", dependencies: { undici: "^8.0.0" } },
          "node_modules/undici": { version: "7.27.2" },
        },
      }),
    );
    expect(records(await buildResidualRiskInventory(root))).toHaveLength(0);
  });

  test("rejects incomplete or controlled topologies", async () => {
    expect(await scan(positive, "7.27.2", "devDependencies")).toHaveLength(0);
    expect(
      await scan(
        positive.replace("req.query.target", '"https://first.internal"'),
      ),
    ).toHaveLength(0);
    expect(
      await scan(positive.replace("authorization", "x-request-id")),
    ).toHaveLength(0);
    expect(
      await scan(
        positive.replace(
          "dispatcher: proxy,\n    headers",
          'dispatcher: new Socks5ProxyAgent("socks5://127.0.0.1:1080"),\n    headers',
        ),
      ),
    ).toHaveLength(0);
    const reversed = positive
      .replace(
        "  await request(req.query.target, { dispatcher: proxy });\n  return request",
        "  const result = await request",
      )
      .replace(
        "  });\n}",
        "  });\n  await request(req.query.target, { dispatcher: proxy });\n  return result;\n}",
      );
    expect(await scan(reversed)).toHaveLength(0);
  });

  test("rejects local lookalikes and reassigned agents", async () => {
    expect(
      await scan(positive.replace('from "undici"', 'from "./undici.js"')),
    ).toHaveLength(0);
    expect(
      await scan(
        positive.replace(
          "export async function forward(req) {",
          "export async function forward(req) {\n  proxy = otherAgent;",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        positive
          .replace(
            'import { Socks5ProxyAgent, request } from "undici";',
            'let { Socks5ProxyAgent, request } = require("undici");',
          )
          .replace(
            "const proxy = new Socks5ProxyAgent",
            "request = localRequest;\nconst proxy = new Socks5ProxyAgent",
          ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        positive
          .replace(
            'import { Socks5ProxyAgent, request } from "undici";',
            'import * as net from "undici";',
          )
          .replace(
            "const proxy = new Socks5ProxyAgent",
            "net.request = localRequest;\nconst proxy = new net.Socks5ProxyAgent",
          )
          .replaceAll("request(", "net.request("),
      ),
    ).toHaveLength(0);
  });

  test("keeps the exact fixture pair source-identical across the repair", async () => {
    const affected = join(
      benchmarkRoot,
      "fixtures",
      "node-undici-socks5-cross-origin-routing",
    );
    const repaired = join(
      benchmarkRoot,
      "fixtures",
      "node-undici-socks5-per-origin-pools",
    );
    expect(await readFile(join(affected, "src", "server.js"), "utf8")).toBe(
      await readFile(join(repaired, "src", "server.js"), "utf8"),
    );
    const affectedPackage = JSON.parse(
      await readFile(join(affected, "package.json"), "utf8"),
    ) as { dependencies: { undici: string } };
    const repairedPackage = JSON.parse(
      await readFile(join(repaired, "package.json"), "utf8"),
    ) as { dependencies: { undici: string } };
    expect(affectedPackage.dependencies.undici).toBe("7.27.2");
    expect(repairedPackage.dependencies.undici).toBe("7.28.0");
    expect(records(await buildResidualRiskInventory(affected))).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(repaired))).toHaveLength(0);
  });

  test("requires the bounded real-package differential and impact discipline", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-undici-socks5-cross-origin-routing");
    expect(prompt).toContain("GHSA-hm92-r4w5-c3mj");
    expect(prompt).toContain("7.23.0 through 7.27.x");
    expect(prompt).toContain("two disposable loopback HTTP origins");
    expect(prompt).toContain("inert fixed authorization marker only");
    expect(prompt).toContain("Report CWE-346");
    expect(prompt).toContain(
      "never use a real credential or external endpoint",
    );
  });
});
