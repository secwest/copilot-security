import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

const benchmarkFixtures = join(
  process.cwd(),
  "..",
  "..",
  "benchmarks",
  "fixtures",
);
const temporaryPaths: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

describe("residual risk inventory", () => {
  test("puts exact archive path and filesystem-write evidence in the correction prompt", async () => {
    const inventory = await buildResidualRiskInventory(
      join(benchmarkFixtures, "python-path-traversal"),
    );

    expect(inventory).toContain('"archive-or-attacker-path"');
    expect(inventory).toContain('"filesystem-write"');
    expect(inventory).toContain("entry.filename");
    expect(inventory).toContain("target.write_bytes");
  });

  test("retains nearby mitigating controls so the model can reject safe flows", async () => {
    const inventory = await buildResidualRiskInventory(
      join(benchmarkFixtures, "python-safe-path"),
    );

    expect(inventory).toContain("entry.filename");
    expect(inventory).toContain("root not in target.parents");
    expect(inventory).toContain("raise ValueError");
  });

  test("surfaces object lookup and ownership boundaries together", async () => {
    const inventory = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-safe-authorization"),
    );

    expect(inventory).toContain('"query-or-object-lookup"');
    expect(inventory).toContain('"authorization-boundary"');
    expect(inventory).toContain("customerId");
  });

  test("pairs request input with SQL execution and parameterization evidence", async () => {
    const vulnerable = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-sql-injection"),
    );
    const safe = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-safe-sql"),
    );

    expect(vulnerable).toContain('"untrusted-input"');
    expect(vulnerable).toContain('"query-or-object-lookup"');
    expect(vulnerable).toContain("request.query.email");
    expect(vulnerable).toContain("SELECT id, email");
    expect(safe).toContain("WHERE email = $1");
    expect(safe).toContain("[email]");
  });

  test("surfaces SSRF input and fixed-destination controls", async () => {
    const vulnerable = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-ssrf"),
    );
    const safe = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-safe-fetch"),
    );

    expect(vulnerable).toContain('"untrusted-input"');
    expect(vulnerable).toContain('"network-request"');
    expect(vulnerable).toContain("fetch(target");
    expect(safe).toContain("assets.example.internal");
    expect(safe).toContain("ASSET.test(asset)");
    expect(safe).toContain('redirect: \\"error\\"');
  });

  test("surfaces unsafe deserialization and bounded JSON controls", async () => {
    const vulnerable = await buildResidualRiskInventory(
      join(benchmarkFixtures, "python-unsafe-deserialization"),
    );
    const safe = await buildResidualRiskInventory(
      join(benchmarkFixtures, "python-safe-json"),
    );

    expect(vulnerable).toContain('"untrusted-input"');
    expect(vulnerable).toContain('"parser-or-deserializer"');
    expect(vulnerable).toContain("pickle.loads(request.body)");
    expect(safe).toContain("len(request.body) > 4096");
    expect(safe).toContain('{\\"theme\\", \\"locale\\"}');
    expect(safe).toContain("Unexpected preference fields");
    expect(safe).not.toContain('"process-or-shell"');
  });

  test("surfaces reflected HTML and nearby escaping controls", async () => {
    const vulnerable = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-reflected-xss"),
    );
    const safe = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-safe-html"),
    );

    expect(vulnerable).toContain('"untrusted-input"');
    expect(vulnerable).toContain('"browser-or-response-injection"');
    expect(vulnerable).toContain("response.type");
    expect(vulnerable).toContain("${name}");
    expect(safe).toContain("escapeHtml");
  });

  test("pairs decoded bearer claims with complete signature verification", async () => {
    const vulnerable = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-jwt-bypass"),
    );
    const safe = await buildResidualRiskInventory(
      join(benchmarkFixtures, "javascript-safe-jwt"),
    );

    expect(vulnerable).toContain('"untrusted-input"');
    expect(vulnerable).toContain('"authentication-or-session"');
    expect(vulnerable).toContain("jwt.decode(token)");
    expect(vulnerable).toContain("claims?.admin");
    expect(safe).toContain("jwt.verify");
    expect(safe).toContain('algorithms: [\\"RS256\\"]');
    expect(safe).toContain('audience: \\"admin-api\\"');
    expect(safe).toContain('issuer: \\"https://identity.example\\"');
  });

  test("pairs external-entity parser switches with bounded defused XML", async () => {
    const vulnerable = await buildResidualRiskInventory(
      join(benchmarkFixtures, "python-xxe"),
    );
    const safe = await buildResidualRiskInventory(
      join(benchmarkFixtures, "python-safe-xml"),
    );

    expect(vulnerable).toContain('"untrusted-input"');
    expect(vulnerable).toContain('"xml-or-entity-parser"');
    expect(vulnerable).toContain("load_dtd=True");
    expect(vulnerable).toContain("resolve_entities=True");
    expect(vulnerable).toContain("no_network=False");
    expect(safe).toContain("defusedxml.ElementTree");
    expect(safe).toContain("len(request.body) > 65536");
  });

  test("prioritizes critical sinks instead of letting noisy files exhaust the prompt", async () => {
    const repository = await mkdtemp(
      join(tmpdir(), "copilot-security-residual-risk-"),
    );
    temporaryPaths.push(repository);
    await writeFile(
      join(repository, "signals.py"),
      `${Array.from({ length: 120 }, (_, index) => `open("file-${index}")`).join("\n")}
subprocess.run(user_input, shell=True)
`,
    );

    const records = (await buildResidualRiskInventory(repository))
      .split("\n")
      .map((line) => JSON.parse(line) as { categories: string[] });

    expect(records).toHaveLength(96);
    expect(records[0]?.categories).toContain("process-or-shell");
  });
});
