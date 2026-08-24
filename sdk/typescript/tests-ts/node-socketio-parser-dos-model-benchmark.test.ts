import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  frameworkModel?: {
    id: string;
    source: { kind: string; path: string; line: number };
    sink: { kind: string; path: string; line: number; cweIds: string[] };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
    candidateControls: Array<{ kind: string; path: string; line: number }>;
  };
}

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

function records(inventory: string): FrameworkRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as FrameworkRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id ===
        "node-http-socketio-parser-zero-attachment-dos",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-socketio-parser-dos-"),
  );
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  source: string,
  options: {
    packageName?: string;
    version?: string;
    section?: "dependencies" | "devDependencies";
    path?: string;
  } = {},
): Promise<void> {
  const directory = join(root, id);
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({
      name: id,
      private: true,
      [options.section ?? "dependencies"]: {
        [options.packageName ?? "socket.io-parser"]: options.version ?? "4.2.6",
      },
    }),
  );
  const sourcePath = join(directory, options.path ?? "server.mjs");
  await mkdir(resolve(sourcePath, ".."), { recursive: true });
  await writeFile(sourcePath, source);
}

const namedSource =
  'import { Decoder } from "socket.io-parser";\nconst decoder = new Decoder();\ndecoder.add(req.body.packet);';

describe("socket.io-parser zero-attachment denial-of-service framework model", () => {
  test("supports official Decoder module bindings on a persistent instance", async () => {
    const root = await repository();
    const cases = [
      [
        "named",
        'import { Decoder as PacketDecoder } from "socket.io-parser";\nconst decoder = new PacketDecoder();\ndecoder.add(req.body.packet);',
      ],
      [
        "namespace",
        'import * as parser from "socket.io-parser";\nconst decoder = new parser.Decoder();\ndecoder.add(request.data);',
      ],
      [
        "default-interop",
        'import parser from "socket.io-parser";\nconst decoder = new parser.Decoder();\ndecoder.add(ctx.request.body);',
      ],
      [
        "typescript-import-equals",
        'import parser = require("socket.io-parser");\nconst decoder = new parser.Decoder();\ndecoder.add(request.body);',
      ],
      [
        "commonjs-receiver",
        'const parser = require("socket.io-parser");\nconst decoder = new parser.Decoder();\ndecoder.add(req.data);',
      ],
      [
        "commonjs-member",
        'const PacketDecoder = require("socket.io-parser").Decoder;\nconst decoder = new PacketDecoder();\ndecoder.add(req.body);',
      ],
      [
        "commonjs-destructured",
        'const { Decoder: PacketDecoder } = require("socket.io-parser");\nconst decoder = new PacketDecoder();\ndecoder.add(request.body.packet);',
      ],
      [
        "exported-instance",
        'import { Decoder } from "socket.io-parser";\nexport const decoder = new Decoder();\ndecoder.add(req.body.packet);',
      ],
    ] as const;
    await Promise.all(cases.map(([id, source]) => writeCase(root, id, source)));
    const found = records(await buildResidualRiskInventory(root));
    expect(found).toHaveLength(cases.length);
    for (const [id] of cases) {
      const record = found.find(({ path }) => path === `${id}/server.mjs`);
      expect(record?.frameworkModel?.sink.kind).toBe(
        "vulnerable-socketio-parser-zero-attachment-dos",
      );
      expect(record?.frameworkModel?.sink.cweIds).toEqual([
        "CWE-400",
        "CWE-20",
        "CWE-754",
      ]);
      expect(record?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
        "socket.io-parser@4.2.6:manifest-exact:zero-attachment-buffer-retention",
      );
    }
  });

  test("enforces all three repaired branch boundaries", async () => {
    const root = await repository();
    const cases = [
      ["v2-affected", "2.4.0", true],
      ["v3-3-affected", "3.3.5", true],
      ["v3-3-fixed", "3.3.6", false],
      ["v3-4-first", "3.4.0", true],
      ["v3-4-affected", "3.4.4", true],
      ["v3-4-fixed", "3.4.5", false],
      ["v4-first", "4.0.0", true],
      ["v4-affected", "4.2.6", true],
      ["v4-fixed", "4.2.7", false],
      ["v5-unaffected", "5.0.0", false],
    ] as const;
    await Promise.all(
      cases.map(([id, version]) =>
        writeCase(root, id, namedSource, { version }),
      ),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path).sort()).toEqual(
      cases
        .filter(([, , affected]) => affected)
        .map(([id]) => `${id}/server.mjs`)
        .sort(),
    );
  });

  test("requires module-scope parser state that survives later frames", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(root, "module-scope", namedSource),
      writeCase(
        root,
        "handler-local",
        'import { Decoder } from "socket.io-parser";\nexport function decode(req) {\n  const decoder = new Decoder();\n  decoder.add(req.body.packet);\n}',
      ),
      writeCase(
        root,
        "block-local",
        'import { Decoder } from "socket.io-parser";\nif (enabled) {\n  const decoder = new Decoder();\n  decoder.add(req.body.packet);\n}',
      ),
      writeCase(
        root,
        "unrelated-local",
        'import { Decoder } from "socket.io-parser";\nconst decoder = new Decoder();\nexport function decode(req) {\n  const decoder = localDecoder();\n  decoder.add(req.body.packet);\n}',
      ),
    ]);
    expect(
      records(await buildResidualRiskInventory(root)).map(({ path }) => path),
    ).toEqual(["module-scope/server.mjs"]);
  });

  test("rejects fixed input, wrong APIs, replacement, shadowing, and tests", async () => {
    const root = await repository();
    await Promise.all([
      writeCase(
        root,
        "fixed-input",
        'import { Decoder } from "socket.io-parser";\nconst decoder = new Decoder();\ndecoder.add(\'50-["evt"]\');',
      ),
      writeCase(
        root,
        "encoder",
        'import { Encoder } from "socket.io-parser";\nconst decoder = new Encoder();\ndecoder.add(req.body.packet);',
      ),
      writeCase(root, "wrong-package", namedSource, {
        packageName: "socket.io-msgpack-parser",
      }),
      writeCase(
        root,
        "reassigned-binding",
        'import { Decoder } from "socket.io-parser";\nDecoder = LocalDecoder;\nconst decoder = new Decoder();\ndecoder.add(req.body.packet);',
      ),
      writeCase(
        root,
        "replaced-member",
        'import * as parser from "socket.io-parser";\nparser.Decoder = LocalDecoder;\nconst decoder = new parser.Decoder();\ndecoder.add(req.body.packet);',
      ),
      writeCase(
        root,
        "reassigned-instance",
        'import { Decoder } from "socket.io-parser";\nlet decoder = new Decoder();\ndecoder = localDecoder;\ndecoder.add(req.body.packet);',
      ),
      writeCase(
        root,
        "replaced-add",
        'import { Decoder } from "socket.io-parser";\nconst decoder = new Decoder();\ndecoder.add = localAdd;\ndecoder.add(req.body.packet);',
      ),
      writeCase(
        root,
        "wrapper-shadow",
        'import { Decoder } from "socket.io-parser";\nconst decoder = new Decoder();\nexport function decode(decoder, req) { decoder.add(req.body.packet); }',
      ),
      writeCase(root, "development-only", namedSource, {
        section: "devDependencies",
      }),
      writeCase(root, "range-without-lock", namedSource, {
        version: "^4.2.0",
      }),
      writeCase(root, "test-path", namedSource, { path: "test/server.mjs" }),
    ]);
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("requires fresh declaration-consistent npm lock proof", async () => {
    const root = await repository();
    for (const [id, lockfileVersion] of [
      ["locked-v2", 2],
      ["locked-v3", 3],
    ] as const) {
      await writeCase(root, id, namedSource, { version: "^4.2.0" });
      await writeFile(
        join(root, id, "package-lock.json"),
        JSON.stringify({
          name: id,
          lockfileVersion,
          packages: {
            "": { dependencies: { "socket.io-parser": "^4.2.0" } },
            "node_modules/socket.io-parser": { version: "4.2.6" },
          },
        }),
      );
    }
    await writeCase(root, "inconsistent", namedSource, {
      version: "^4.2.0",
    });
    await writeFile(
      join(root, "inconsistent", "package-lock.json"),
      JSON.stringify({
        name: "inconsistent",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { "socket.io-parser": "^3.4.0" } },
          "node_modules/socket.io-parser": { version: "4.2.6" },
        },
      }),
    );
    await writeCase(root, "legacy-lock", namedSource, {
      version: "^4.2.0",
    });
    await writeFile(
      join(root, "legacy-lock", "package-lock.json"),
      JSON.stringify({
        name: "legacy-lock",
        lockfileVersion: 1,
        dependencies: { "socket.io-parser": { version: "4.2.6" } },
      }),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "locked-v2/server.mjs",
      "locked-v3/server.mjs",
    ]);
    for (const record of found) {
      expect(record.frameworkModel?.sink.kind).toBe(
        "lock-resolved-vulnerable-socketio-parser-zero-attachment-dos",
      );
      expect(record.frameworkModel?.propagators.at(-1)?.symbol).toBe(
        "socket.io-parser@4.2.6:npm-lockfile:zero-attachment-buffer-retention",
      );
    }
  });

  test("keeps the package-backed benchmark pair source-identical and strict", async () => {
    const vulnerable = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-socketio-parser-dos",
    );
    const patched = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-socketio-parser",
    );
    const found = records(await buildResidualRiskInventory(vulnerable));
    expect(found).toHaveLength(1);
    expect(records(await buildResidualRiskInventory(patched))).toEqual([]);
    expect(found[0]?.frameworkModel?.source.line).toBe(7);
    expect(found[0]?.frameworkModel?.sink.line).toBe(6);
    expect(found[0]?.frameworkModel?.sink.kind).toBe(
      "vulnerable-socketio-parser-zero-attachment-dos",
    );
    expect(found[0]?.frameworkModel?.sink.cweIds).toEqual([
      "CWE-400",
      "CWE-20",
      "CWE-754",
    ]);
    expect(found[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "socket.io-parser@4.2.6:manifest-exact:zero-attachment-buffer-retention",
    );
    for (const path of [
      join("src", "server.js"),
      join("src", "gateway.js"),
      join("src", "service.js"),
      join("src", "storage.js"),
      "witness.mjs",
    ]) {
      expect(await readFile(join(vulnerable, path), "utf8")).toBe(
        await readFile(join(patched, path), "utf8"),
      );
    }
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-socketio-parser-dos-manifest.json"),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        expected: unknown[];
        findingsPaths: string[];
      }>;
    };
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-multi-hop-socketio-parser-dos",
      "node-multi-hop-patched-socketio-parser",
    ]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);
    expect(manifest.cases[0]?.findingsPaths).toHaveLength(3);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.findingsPaths).toHaveLength(3);
    expect(manifest.cases[1]?.expected).toEqual([]);
  });

  test("teaches exact state, version, mitigation, and impact boundaries", () => {
    const prompt = scanQualityGatePrompt("inventory-row");
    expect(prompt).toContain(
      "node-http-socketio-parser-zero-attachment-dos rows",
    );
    expect(prompt).toContain("3.3.6");
    expect(prompt).toContain("3.4.5");
    expect(prompt).toContain("4.2.7");
    expect(prompt).toContain('50-["evt"]');
    expect(prompt).toContain("module-scope persistent Decoder");
    expect(prompt).toContain("maxAttachments does not repair");
    expect(prompt).toContain("CWE-20 and CWE-754");
  });
});
