import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import { buildResidualRiskInventory } from "../src/residual-risk.js";

interface FrameworkRecord {
  path: string;
  line: number;
  categories: string[];
  frameworkModel?: {
    id: string;
    source: { path: string; line: number };
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
        "node-http-nodemailer-raw-access-policy-bypass",
    );
}

async function repository(): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "copilot-security-nodemailer-model-"),
  );
  temporaryPaths.push(root);
  return root;
}

async function writeCase(
  root: string,
  id: string,
  source: string,
  options: {
    version?: string;
    section?: "dependencies" | "devDependencies";
    dependencyName?: string;
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
        [options.dependencyName ?? "nodemailer"]: options.version ?? "9.0.0",
      },
    }),
  );
  const sourcePath = join(directory, options.path ?? "server.mjs");
  await mkdir(resolve(sourcePath, ".."), { recursive: true });
  await writeFile(sourcePath, source);
}

const route = (
  factory: string,
  policy = "disableFileAccess: true, disableUrlAccess: true",
  message = "to: request.body.to, raw: request.body.raw",
): string =>
  `${factory}\nconst transport = create({ streamTransport: true, ${policy} });\nexport function deliver(request) { return transport.sendMail({ ${message} }); }\n`;

describe("Nodemailer raw access-policy bypass model", () => {
  test("supports exact official factory bindings on vulnerable releases", async () => {
    const root = await repository();
    await writeCase(
      root,
      "default",
      'import nodemailer from "nodemailer";\nconst transport = nodemailer.createTransport({ disableFileAccess: true, disableUrlAccess: true });\nexport function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); }\n',
    );
    await writeCase(
      root,
      "namespace",
      'import * as mailer from "nodemailer";\nconst transport = mailer.createTransport({ disableFileAccess: true, disableUrlAccess: true });\nexport function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); }\n',
    );
    await writeCase(
      root,
      "named",
      route('import { createTransport as create } from "nodemailer";'),
    );
    await writeCase(
      root,
      "commonjs",
      'const mailer = require("nodemailer");\nconst transport = mailer.createTransport({ disableFileAccess: true, disableUrlAccess: true });\nexports.deliver = function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); };\n',
    );
    await writeCase(
      root,
      "destructured",
      route('const { createTransport: create } = require("nodemailer");'),
    );
    await writeCase(
      root,
      "import-equals",
      'import mailer = require("nodemailer");\nconst transport = mailer.createTransport({ disableFileAccess: true, disableUrlAccess: true });\nexport function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); }\n',
    );
    await writeCase(
      root,
      "inline-require",
      'const transport = require("nodemailer").createTransport({ disableFileAccess: true, disableUrlAccess: true });\nexports.deliver = function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); };\n',
    );

    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "commonjs/server.mjs",
      "default/server.mjs",
      "destructured/server.mjs",
      "import-equals/server.mjs",
      "inline-require/server.mjs",
      "named/server.mjs",
      "namespace/server.mjs",
    ]);
    expect(
      found.every((record) =>
        record.frameworkModel?.sink.kind.endsWith(
          "vulnerable-nodemailer-raw-file-url-access-policy-bypass",
        ),
      ),
    ).toBe(true);
  });

  test("distinguishes file, URL, combined, and message-level deny policies", async () => {
    const root = await repository();
    await writeCase(
      root,
      "file",
      route(
        'import { createTransport as create } from "nodemailer";',
        "disableFileAccess: true",
      ),
    );
    await writeCase(
      root,
      "url",
      route(
        'import { createTransport as create } from "nodemailer";',
        "disableUrlAccess: true",
      ),
    );
    await writeCase(
      root,
      "message",
      route(
        'import { createTransport as create } from "nodemailer";',
        "streamTransport: true",
        "to: request.body.to, raw: request.body.raw, disableFileAccess: true, disableUrlAccess: true",
      ),
    );
    await writeCase(
      root,
      "none",
      route(
        'import { createTransport as create } from "nodemailer";',
        "streamTransport: true",
      ),
    );
    await writeCase(
      root,
      "false",
      route(
        'import { createTransport as create } from "nodemailer";',
        "disableFileAccess: false, disableUrlAccess: false",
      ),
    );
    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "file/server.mjs",
      "message/server.mjs",
      "url/server.mjs",
    ]);
    expect(found.map((record) => record.frameworkModel?.sink.cweIds)).toEqual([
      ["CWE-73", "CWE-200"],
      ["CWE-73", "CWE-918", "CWE-200"],
      ["CWE-918", "CWE-200"],
    ]);
  });

  test("requires raw attacker flow, an attacker recipient, exact options, and sendMail", async () => {
    const root = await repository();
    const factory = 'import { createTransport as create } from "nodemailer";';
    await writeCase(root, "positive", route(factory));
    await writeCase(
      root,
      "attachment",
      route(
        factory,
        undefined,
        "to: request.body.to, attachments: [{ path: request.body.path }]",
      ),
    );
    await writeCase(
      root,
      "fixed-recipient",
      route(
        factory,
        undefined,
        'to: "owner@example.test", raw: request.body.raw',
      ),
    );
    await writeCase(
      root,
      "fixed-raw",
      route(
        factory,
        undefined,
        'to: request.body.to, raw: "Subject: fixed\\r\\n\\r\\nbody"',
      ),
    );
    await writeCase(
      root,
      "spread",
      route(
        factory,
        undefined,
        "...request.body, to: request.body.to, raw: request.body.raw",
      ),
    );
    await writeCase(
      root,
      "wrong-method",
      `${factory}\nconst transport = create({ disableFileAccess: true });\nexport function deliver(request) { return transport.verify({ to: request.body.to, raw: request.body.raw }); }\n`,
    );
    await writeCase(
      root,
      "split-sources",
      `${factory}\nconst transport = create({ disableFileAccess: true });\nexport function deliver(rawRequest, recipientRequest) { return transport.sendMail({ to: recipientRequest.body.to, raw: rawRequest.body.raw }); }\n`,
    );
    await writeCase(
      root,
      "options-spread",
      `${factory}\nconst defaults = request.body.options;\nconst transport = create({ ...defaults, disableFileAccess: true });\nexport function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); }\n`,
    );
    expect(
      records(await buildResidualRiskInventory(root)).map(({ path }) => path),
    ).toEqual(["positive/server.mjs"]);
  });

  test("fails closed on patched, development-only, wrong, unlocked, and inconsistent metadata", async () => {
    const root = await repository();
    const source = route(
      'import { createTransport as create } from "nodemailer";',
    );
    await writeCase(root, "vulnerable", source);
    await writeCase(root, "patched", source, { version: "9.0.1" });
    await writeCase(root, "development", source, {
      section: "devDependencies",
    });
    await writeCase(root, "wrong-package", source, {
      dependencyName: "mail-sender",
    });
    await writeCase(root, "unlocked", source, { version: "^9.0.0" });

    const valid = join(root, "valid-lock");
    await mkdir(valid);
    await writeFile(
      join(valid, "package.json"),
      JSON.stringify({
        name: "valid-lock",
        dependencies: { nodemailer: "^9.0.0" },
      }),
    );
    await writeFile(
      join(valid, "package-lock.json"),
      JSON.stringify({
        name: "valid-lock",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { nodemailer: "^9.0.0" } },
          "node_modules/nodemailer": { version: "9.0.0" },
        },
      }),
    );
    await writeFile(join(valid, "server.mjs"), source);

    const stale = join(root, "stale-lock");
    await mkdir(stale);
    await writeFile(
      join(stale, "package.json"),
      JSON.stringify({
        name: "stale-lock",
        dependencies: { nodemailer: "^9.0.0" },
      }),
    );
    await writeFile(
      join(stale, "package-lock.json"),
      JSON.stringify({
        name: "stale-lock",
        lockfileVersion: 3,
        packages: {
          "": { dependencies: { nodemailer: "~9.0.0" } },
          "node_modules/nodemailer": { version: "9.0.0" },
        },
      }),
    );
    await writeFile(join(stale, "server.mjs"), source);

    const legacy = join(root, "legacy-lock");
    await mkdir(legacy);
    await writeFile(
      join(legacy, "package.json"),
      JSON.stringify({
        name: "legacy-lock",
        dependencies: { nodemailer: "^9.0.0" },
      }),
    );
    await writeFile(
      join(legacy, "package-lock.json"),
      JSON.stringify({
        name: "legacy-lock",
        lockfileVersion: 1,
        dependencies: { nodemailer: { version: "9.0.0" } },
      }),
    );
    await writeFile(join(legacy, "server.mjs"), source);

    const found = records(await buildResidualRiskInventory(root));
    expect(found.map(({ path }) => path)).toEqual([
      "valid-lock/server.mjs",
      "vulnerable/server.mjs",
    ]);
    expect(found[0]?.frameworkModel?.sink.kind).toStartWith("lock-resolved-");
  });

  test("rejects reassigned, shadowed, local-lookalike, and test-only call paths", async () => {
    const root = await repository();
    await writeCase(
      root,
      "reassigned-factory",
      'import { createTransport as create } from "nodemailer";\ncreate = localFactory;\nconst transport = create({ disableFileAccess: true });\nexport function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); }\n',
    );
    await writeCase(
      root,
      "reassigned-factory-member",
      'import nodemailer from "nodemailer";\nnodemailer.createTransport = localFactory;\nconst transport = nodemailer.createTransport({ disableFileAccess: true });\nexport function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); }\n',
    );
    await writeCase(
      root,
      "reassigned-transport",
      'import { createTransport as create } from "nodemailer";\nlet transport = create({ disableFileAccess: true });\ntransport = localTransport;\nexport function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); }\n',
    );
    await writeCase(
      root,
      "shadowed",
      'import nodemailer from "nodemailer";\nexport function deliver(nodemailer, request) { const transport = nodemailer.createTransport({ disableFileAccess: true }); return transport.sendMail({ to: request.body.to, raw: request.body.raw }); }\n',
    );
    await writeCase(
      root,
      "lookalike",
      'import "nodemailer";\nconst create = localMailer.createTransport;\nconst transport = create({ disableFileAccess: true });\nexport function deliver(request) { return transport.sendMail({ to: request.body.to, raw: request.body.raw }); }\n',
    );
    await writeCase(
      root,
      "test-path",
      route('import { createTransport as create } from "nodemailer";'),
      { path: "test/mailer.test.mjs" },
    );
    expect(records(await buildResidualRiskInventory(root))).toEqual([]);
  });

  test("preserves dependency provenance and the full source-identical benchmark path", async () => {
    const vulnerableRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-nodemailer-raw-access",
    );
    const patchedRoot = join(
      benchmarkRoot,
      "fixtures",
      "node-multi-hop-patched-nodemailer-raw-access",
    );
    const found = records(await buildResidualRiskInventory(vulnerableRoot));
    expect(found).toHaveLength(1);
    expect(found[0]?.frameworkModel).toMatchObject({
      source: { path: "src/server.js", line: 8 },
      sink: {
        path: "src/mailer.js",
        line: 11,
        kind: "vulnerable-nodemailer-raw-file-url-access-policy-bypass",
        cweIds: ["CWE-73", "CWE-918", "CWE-200"],
      },
    });
    expect(found[0]?.frameworkModel?.propagators).toContainEqual({
      kind: "nodemailer-runtime-dependency",
      path: "package.json",
      line: 6,
      symbol: "nodemailer@9.0.0:manifest-exact:raw-access-policy-bypass",
    });
    expect(found[0]?.frameworkModel?.candidateControls).toEqual(
      expect.arrayContaining([
        {
          kind: "nodemailer-disable-file-access-policy",
          path: "src/mailer.js",
          line: 3,
        },
        {
          kind: "nodemailer-disable-url-access-policy",
          path: "src/mailer.js",
          line: 3,
        },
      ]),
    );
    expect(records(await buildResidualRiskInventory(patchedRoot))).toEqual([]);
    for (const relative of [
      "src/server.js",
      "src/gateway.js",
      "src/service.js",
      "src/mailer.js",
    ]) {
      expect(await readFile(join(vulnerableRoot, relative), "utf8")).toBe(
        await readFile(join(patchedRoot, relative), "utf8"),
      );
    }
  });

  test("keeps the strict manifest and reviewer contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "node-nodemailer-raw-access-manifest.json"),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{
        id: string;
        findingsPaths: string[];
        expected: unknown[];
      }>;
    };
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "node-multi-hop-nodemailer-raw-access",
      "node-multi-hop-patched-nodemailer-raw-access",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.thresholds["minPrecision"]).toBe(1);
    expect(manifest.thresholds["minRecall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositivesPerRun"]).toBe(0);

    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("node-http-nodemailer-raw-access-policy-bypass");
    expect(prompt).toContain("GHSA-p6gq-j5cr-w38f");
    expect(prompt).toContain("9.0.1");
    expect(prompt).toContain("EFILEACCESS");
    expect(prompt).toContain("attacker-controlled recipient");
  });
});
