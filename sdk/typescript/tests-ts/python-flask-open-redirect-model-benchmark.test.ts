import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

const modelId = "python-flask-open-redirect";
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

async function writeRepository(
  root: string,
  files: Readonly<Record<string, string>>,
): Promise<void> {
  for (const [path, contents] of Object.entries(files)) {
    const absolute = join(root, path);
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, contents, "utf8");
  }
}

function models(inventory: string): any[] {
  return inventory === ""
    ? []
    : inventory
        .split("\n")
        .map((line) => JSON.parse(line))
        .flatMap((record) =>
          record.frameworkModel?.id === modelId ? [record.frameworkModel] : [],
        );
}

describe("Flask open-redirect model", () => {
  test("keeps a strict executable exploit/control benchmark contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-flask-open-redirect-manifest.json"),
        "utf8",
      ),
    );

    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }: { id: string }) => id)).toEqual([
      "python-flask-open-redirect",
      "python-flask-safe-local-redirect",
    ]);
    expect(manifest.cases[0].expected[0]).toMatchObject({
      id: modelId,
      cwe: ["CWE-601"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(
      manifest.cases[0].expected[0].requiredValidationTextAnyOf,
    ).toHaveLength(7);
    expect(
      manifest.cases[0].expected[0].requiredAttackPathTextAnyOf,
    ).toHaveLength(7);
    expect(manifest.cases[0].expected[0].forbiddenText.length).toBeGreaterThan(
      0,
    );
    expect(manifest.cases[1].expected).toEqual([]);
  });

  test("keeps a strict POST form exploit/control benchmark contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-flask-post-open-redirect-manifest.json"),
        "utf8",
      ),
    );
    expect(manifest.schemaVersion).toBe("1.0");
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }: { id: string }) => id)).toEqual([
      "python-flask-post-open-redirect",
      "python-flask-post-safe-local-redirect",
    ]);
    expect(manifest.cases[0].expected[0]).toMatchObject({
      id: modelId,
      cwe: ["CWE-601"],
      requireValidation: true,
      requireAttackPath: true,
      requireCodeEvidence: true,
    });
    expect(manifest.cases[0].expected[0].requiredValidationTextAnyOf).toEqual(
      expect.arrayContaining([
        expect.arrayContaining(["request.form"]),
        expect.arrayContaining(['methods=["POST"]']),
      ]),
    );
    expect(manifest.cases[0].expected[0].forbiddenText.length).toBeGreaterThan(
      0,
    );
    expect(manifest.cases[1].expected).toEqual([]);
  });

  test("separates the checked-in root-prefix exploit and fixed-local control", async () => {
    const exploit = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-open-redirect",
    );
    const control = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-safe-local-redirect",
    );
    const exploitModels = models(await buildResidualRiskInventory(exploit));
    const controlModels = models(await buildResidualRiskInventory(control));

    expect(exploitModels).toHaveLength(1);
    expect(exploitModels[0]).toMatchObject({
      scope: "same-file",
      source: {
        kind: "flask-request-query-string",
        path: "src/server.py",
        line: 7,
      },
      sink: {
        kind: "flask-redirect-location",
        path: "src/server.py",
        line: 9,
        cweIds: ["CWE-601"],
      },
    });
    expect(controlModels).toHaveLength(0);
  });

  test("separates the checked-in POST form exploit and fixed-local control", async () => {
    const exploit = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-post-open-redirect",
    );
    const control = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-post-safe-local-redirect",
    );
    const exploitModels = models(await buildResidualRiskInventory(exploit));
    const controlModels = models(await buildResidualRiskInventory(control));

    expect(exploitModels).toHaveLength(1);
    expect(exploitModels[0]).toMatchObject({
      source: { kind: "flask-request-form-string" },
      sink: { kind: "flask-redirect-location", cweIds: ["CWE-601"] },
    });
    expect(exploitModels[0].propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "flask-route-form-method" }),
        expect.objectContaining({ kind: "flask-request-form-read" }),
        expect.objectContaining({ kind: "http-location-header-assignment" }),
      ]),
    );
    expect(controlModels).toHaveLength(0);
  });

  test("detects a root-only local prefix but rejects an encoded fixed-local control", async () => {
    const exploit = await mkdtemp(join(tmpdir(), "flask-root-prefix-exploit-"));
    const control = await mkdtemp(join(tmpdir(), "flask-root-prefix-control-"));
    try {
      await writeRepository(exploit, {
        "server.py": [
          "from flask import Flask, redirect, request",
          "app = Flask(__name__)",
          '@app.get("/continue")',
          "def continue_to():",
          '    target = request.args.get("next", "")',
          '    destination = "/" + target',
          "    return redirect(destination, code=307)",
          "",
        ].join("\n"),
      });
      await writeRepository(control, {
        "server.py": [
          "from urllib.parse import quote",
          "from flask import Flask, redirect, request",
          "app = Flask(__name__)",
          '@app.get("/continue")',
          "def continue_to():",
          '    target = request.args.get("next", "")',
          '    destination = "/continue?next=" + quote(target, safe="")',
          "    return redirect(destination, code=307)",
          "",
        ].join("\n"),
      });

      const exploitModels = models(await buildResidualRiskInventory(exploit));
      const controlModels = models(await buildResidualRiskInventory(control));

      expect(exploitModels).toHaveLength(1);
      expect(exploitModels[0].source.kind).toBe("flask-request-query-string");
      expect(exploitModels[0].sink).toEqual({
        kind: "flask-redirect-location",
        path: "server.py",
        line: 7,
        cweIds: ["CWE-601"],
      });
      expect(exploitModels[0].propagators).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            kind: "flask-official-application-factory",
          }),
          expect.objectContaining({ kind: "flask-route" }),
          expect.objectContaining({ kind: "flask-official-request-binding" }),
          expect.objectContaining({ kind: "flask-request-args-read" }),
          expect.objectContaining({ kind: "flask-official-redirect-binding" }),
          expect.objectContaining({ kind: "http-location-header-assignment" }),
        ]),
      );
      expect(controlModels).toHaveLength(0);
    } finally {
      await rm(exploit, { recursive: true, force: true });
      await rm(control, { recursive: true, force: true });
    }
  });

  test("accepts official qualified, named-location, subscript, route, and path-parameter forms", async () => {
    const variants: ReadonlyArray<readonly [string, string]> = [
      [
        "qualified-subscript",
        [
          "import flask as web",
          "app = web.Flask(__name__)",
          '@app.route("/continue")',
          "def continue_to():",
          '    return web.redirect(location=web.request.args["next"], code=307)',
          "",
        ].join("\n"),
      ],
      [
        "path-parameter",
        [
          "from flask import Flask, redirect, request",
          "app = Flask(__name__)",
          '@app.get("/tenant/<tenant>")',
          "def continue_to(tenant):",
          '    target = request.args.get("next")',
          '    return redirect("/" + target)',
          "",
        ].join("\n"),
      ],
    ];

    for (const [name, server] of variants) {
      const root = await mkdtemp(join(tmpdir(), `flask-redirect-${name}-`));
      try {
        await writeRepository(root, { "server.py": server });
        const detected = models(await buildResidualRiskInventory(root));
        expect(detected, name).toHaveLength(1);
        expect(detected[0].sink.cweIds, name).toEqual(["CWE-601"]);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  test("detects form redirects only on exact form-capable routes", async () => {
    const variants: ReadonlyArray<readonly [string, string, string]> = [
      [
        "post-shortcut",
        '@app.post("/continue")',
        'request.form.get("next", "")',
      ],
      ["put-shortcut", '@app.put("/continue")', 'request.form["next"]'],
      ["patch-shortcut", '@app.patch("/continue")', 'request.form.get("next")'],
      [
        "route-methods",
        '@app.route("/continue", methods=["POST"])',
        'request.form.get("next", "")',
      ],
      [
        "route-method-tuple",
        '@app.route("/continue", methods=("GET", "post"))',
        'request.form["next"]',
      ],
    ];
    for (const [name, decorator, read] of variants) {
      const root = await mkdtemp(
        join(tmpdir(), `flask-form-redirect-${name}-`),
      );
      try {
        await writeRepository(root, {
          "server.py": [
            "from flask import Flask, redirect, request",
            "app = Flask(__name__)",
            decorator,
            "def continue_to():",
            `    target = ${read}`,
            '    return redirect("/" + target)',
            "",
          ].join("\n"),
        });
        const detected = models(await buildResidualRiskInventory(root));
        expect(detected, name).toHaveLength(1);
        expect(detected[0], name).toMatchObject({
          source: { kind: "flask-request-form-string" },
        });
        expect(detected[0].propagators, name).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ kind: "flask-route-form-method" }),
            expect.objectContaining({ kind: "flask-request-form-read" }),
          ]),
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  test("preserves request control through a relative redirect wrapper", async () => {
    const root = await mkdtemp(join(tmpdir(), "flask-redirect-wrapper-"));
    try {
      await writeRepository(root, {
        "src/__init__.py": "",
        "src/server.py": [
          "from flask import Flask, request",
          "from .redirects import issue_redirect",
          "app = Flask(__name__)",
          '@app.get("/continue")',
          "def continue_to():",
          '    target = request.args.get("next", "")',
          '    return issue_redirect("/" + target)',
          "",
        ].join("\n"),
        "src/redirects.py": [
          "from flask import redirect",
          "def issue_redirect(destination):",
          "    return redirect(destination, code=307)",
          "",
        ].join("\n"),
      });
      const detected = models(await buildResidualRiskInventory(root));
      expect(detected).toHaveLength(1);
      expect(detected[0].scope).toBe("cross-file-wrapper");
      expect(detected[0].sink).toMatchObject({
        path: "src/redirects.py",
        line: 3,
        cweIds: ["CWE-601"],
      });
      expect(detected[0].propagators).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "flask-route" }),
          expect.objectContaining({ kind: "flask-request-args-read" }),
          expect.objectContaining({ kind: "flask-official-redirect-binding" }),
        ]),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("fails closed on Flask lookalikes, unstable bindings, ambiguous routes, and opaque transformations", async () => {
    const base = [
      "from flask import Flask, redirect, request",
      "app = Flask(__name__)",
      '@app.get("/continue")',
      "def continue_to():",
      '    target = request.args.get("next", "")',
      "    return redirect(target)",
      "",
    ].join("\n");
    const variants: ReadonlyArray<
      readonly [string, string, Readonly<Record<string, string>>?]
    > = [
      [
        "fixed-local-prefix",
        base.replace("redirect(target)", 'redirect("/continue/" + target)'),
      ],
      [
        "request-form",
        base.replace(
          'request.args.get("next", "")',
          'request.form.get("next", "")',
        ),
      ],
      [
        "request-form-default-route",
        base
          .replace('@app.get("/continue")', '@app.route("/continue")')
          .replace("request.args", "request.form"),
      ],
      [
        "request-form-get-only-route",
        base
          .replace(
            '@app.get("/continue")',
            '@app.route("/continue", methods=["GET"])',
          )
          .replace("request.args", "request.form"),
      ],
      [
        "request-form-dynamic-methods",
        base
          .replace(
            "app = Flask(__name__)",
            'app = Flask(__name__)\nMETHODS = ["POST"]',
          )
          .replace(
            '@app.get("/continue")',
            '@app.route("/continue", methods=METHODS)',
          )
          .replace("request.args", "request.form"),
      ],
      [
        "request-form-empty-methods",
        base
          .replace(
            '@app.get("/continue")',
            '@app.route("/continue", methods=[])',
          )
          .replace("request.args", "request.form"),
      ],
      [
        "request-form-delete-shortcut",
        base
          .replace('@app.get("/continue")', '@app.delete("/continue")')
          .replace("request.args", "request.form"),
      ],
      [
        "rebound-request",
        base.replace(
          "app = Flask(__name__)",
          "app = Flask(__name__)\nrequest = object()",
        ),
      ],
      [
        "rebound-redirect",
        base.replace(
          "app = Flask(__name__)",
          "app = Flask(__name__)\nredirect = lambda value: value",
        ),
      ],
      [
        "blueprint",
        base
          .replace("Flask, redirect, request", "Blueprint, redirect, request")
          .replace("Flask(__name__)", 'Blueprint("bp", __name__)'),
      ],
      [
        "dynamic-route",
        base.replace('@app.get("/continue")', "@app.get(route_name)"),
      ],
      [
        "additional-decorator",
        base.replace(
          '@app.get("/continue")',
          '@authorization_required\n@app.get("/continue")',
        ),
      ],
      [
        "opaque-sanitizer",
        base.replace("redirect(target)", "redirect(sanitize(target))"),
      ],
      [
        "unknown-keyword",
        base.replace("redirect(target)", "redirect(target, unexpected=True)"),
      ],
      [
        "local-flask-shadow",
        base,
        {
          "flask/__init__.py":
            "class Flask: pass\nrequest = object()\ndef redirect(value): return value\n",
        },
      ],
    ];

    for (const [name, server, extra = {}] of variants) {
      const root = await mkdtemp(
        join(tmpdir(), `flask-redirect-negative-${name}-`),
      );
      try {
        await writeRepository(root, { "server.py": server, ...extra });
        expect(
          models(await buildResidualRiskInventory(root)),
          name,
        ).toHaveLength(0);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  test("requires Flask boundary and root-prefix evidence in review fields", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-open-redirect",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "flask-redirect-quality-"),
    );
    const finding: any = {
      occurrenceId: "occ_flask_redirect_quality",
      taxonomy: { cwe: ["CWE-601"] },
      locations: [
        { path: "src/server.py", startLine: 7, role: "source" },
        { path: "src/server.py", startLine: 9, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "flask-source",
          path: "src/server.py",
          startLine: 7,
          code: 'request.args.get("next", "")',
          explanation: "Flask request query field.",
          role: "source",
        },
        {
          id: "flask-sink",
          path: "src/server.py",
          startLine: 9,
          code: "redirect(destination, code=307)",
          explanation: "Official Flask redirect Location.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A request value reaches a redirect.",
        method: "source review",
        evidence: ["flask-source", "flask-sink"],
      },
      attackPath: {
        summary: "A request value reaches a redirect.",
        dataflow: {
          source: "flask-source",
          sink: "flask-sink",
          outcome: "redirect",
        },
        evidenceRefs: ["flask-source", "flask-sink"],
      },
    };
    try {
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
      );
      const incomplete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      expect(incomplete).toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(incomplete).toContain(
        "missing_model_specific_attack_path_evidence",
      );

      const contract =
        "The official Flask application factory exposes an app.get route whose remote request.args query field reaches flask.redirect and its Location header. A root-only prefix can form a scheme-relative attacker-selected host; a non-root fixed local prefix, exact same-origin allowlist, or equivalent control is absent, producing a CWE-601 open redirect.";
      finding.validation.summary = contract;
      finding.attackPath.summary = contract;
      await writeFile(
        join(scanDirectory, "findings.json"),
        JSON.stringify({ findings: [finding] }),
      );
      const complete = await buildFindingQualityGapInventory(
        scanDirectory,
        repository,
        inventory,
      );
      expect(complete).not.toContain(
        "missing_model_specific_validation_evidence",
      );
      expect(complete).not.toContain(
        "missing_model_specific_attack_path_evidence",
      );
    } finally {
      await rm(scanDirectory, { recursive: true, force: true });
    }
  });

  test("teaches the reviewer the Flask Location and root-prefix boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"python-flask-open-redirect"}}',
    );
    expect(prompt).toContain("python-flask-open-redirect");
    expect(prompt).toContain("request.args");
    expect(prompt).toContain("request.form");
    expect(prompt).toContain('methods=["POST"]');
    expect(prompt).toContain("flask.redirect");
    expect(prompt).toContain("Location");
    expect(prompt).toContain("root-only");
    expect(prompt).toContain("follow_redirects=False");
    expect(prompt).toContain("CWE-601");
  });
});
