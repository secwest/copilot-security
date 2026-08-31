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

  test("keeps a strict registered-Blueprint exploit/control contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "python-flask-blueprint-open-redirect-manifest.json",
        ),
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
      "python-flask-blueprint-open-redirect",
      "python-flask-blueprint-safe-local-redirect",
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
        expect.arrayContaining(["Flask Blueprint"]),
        expect.arrayContaining(["register_blueprint"]),
      ]),
    );
    expect(manifest.cases[0].expected[0].forbiddenText.length).toBeGreaterThan(
      0,
    );
    expect(manifest.cases[1].expected).toEqual([]);
  });

  test("keeps a strict cross-file Blueprint factory contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "python-flask-cross-file-blueprint-open-redirect-manifest.json",
        ),
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
      "python-flask-cross-file-blueprint-open-redirect",
      "python-flask-cross-file-blueprint-safe-local-redirect",
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
        expect.arrayContaining(["relative import"]),
        expect.arrayContaining(["create_app"]),
        expect.arrayContaining(["register_blueprint"]),
        expect.arrayContaining(["url_prefix"]),
      ]),
    );
    expect(manifest.cases[0].expected[0].forbiddenText.length).toBeGreaterThan(
      0,
    );
    expect(manifest.cases[1].expected).toEqual([]);
  });

  test("keeps a strict nested-Blueprint exploit/control contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "python-flask-nested-blueprint-open-redirect-manifest.json",
        ),
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
      "python-flask-nested-blueprint-open-redirect",
      "python-flask-nested-blueprint-safe-local-redirect",
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
        expect.arrayContaining(["child-to-parent"]),
        expect.arrayContaining(["parent-to-application"]),
        expect.arrayContaining(["request.args"]),
        expect.arrayContaining(["Location header"]),
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

  test("separates the checked-in registered-Blueprint exploit and control", async () => {
    const exploit = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-blueprint-open-redirect",
    );
    const control = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-blueprint-safe-local-redirect",
    );
    const exploitModels = models(await buildResidualRiskInventory(exploit));
    const controlModels = models(await buildResidualRiskInventory(control));

    expect(exploitModels).toHaveLength(1);
    expect(exploitModels[0]).toMatchObject({
      source: {
        kind: "flask-request-query-string",
        path: "src/server.py",
        line: 10,
      },
      sink: {
        kind: "flask-redirect-location",
        path: "src/server.py",
        line: 12,
        cweIds: ["CWE-601"],
      },
    });
    expect(exploitModels[0].propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "flask-official-blueprint-factory",
        }),
        expect.objectContaining({ kind: "flask-blueprint-registration" }),
      ]),
    );
    expect(controlModels).toHaveLength(0);
  });

  test("separates the checked-in cross-file Blueprint factory pair", async () => {
    const exploit = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-cross-file-blueprint-open-redirect",
    );
    const control = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-cross-file-blueprint-safe-local-redirect",
    );
    const exploitModels = models(await buildResidualRiskInventory(exploit));
    const controlModels = models(await buildResidualRiskInventory(control));

    expect(exploitModels).toHaveLength(1);
    expect(exploitModels[0]).toMatchObject({
      source: {
        kind: "flask-request-query-string",
        path: "src/service/redirects.py",
        line: 8,
      },
      sink: {
        kind: "flask-redirect-location",
        path: "src/service/redirects.py",
        line: 11,
        cweIds: ["CWE-601"],
      },
    });
    expect(exploitModels[0].propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "relative-python-blueprint-module-import",
          path: "src/service/__init__.py",
          line: 6,
        }),
        expect.objectContaining({
          kind: "flask-application-factory-function",
          path: "src/service/__init__.py",
          line: 4,
        }),
        expect.objectContaining({
          kind: "flask-blueprint-literal-url-prefix",
          path: "src/service/__init__.py",
          line: 7,
        }),
        expect.objectContaining({
          kind: "flask-application-factory-return",
          path: "src/service/__init__.py",
          line: 8,
        }),
      ]),
    );
    expect(controlModels).toHaveLength(0);
  });

  test("separates the checked-in nested-Blueprint exploit and control", async () => {
    const exploit = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-nested-blueprint-open-redirect",
    );
    const control = join(
      benchmarkRoot,
      "fixtures",
      "python-flask-nested-blueprint-safe-local-redirect",
    );
    const exploitModels = models(await buildResidualRiskInventory(exploit));
    const controlModels = models(await buildResidualRiskInventory(control));

    expect(exploitModels).toHaveLength(1);
    expect(exploitModels[0]).toMatchObject({
      source: {
        kind: "flask-request-query-string",
        path: "src/server.py",
        line: 12,
      },
      sink: {
        kind: "flask-redirect-location",
        path: "src/server.py",
        line: 15,
        cweIds: ["CWE-601"],
      },
    });
    expect(exploitModels[0].propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          kind: "flask-blueprint-nesting",
          path: "src/server.py",
          line: 18,
        }),
        expect.objectContaining({
          kind: "flask-blueprint-registration",
          path: "src/server.py",
          line: 19,
        }),
      ]),
    );
    expect(controlModels).toHaveLength(0);
  });

  test("accepts an exact registered Blueprint route", async () => {
    const root = await mkdtemp(join(tmpdir(), "flask-blueprint-redirect-"));
    try {
      await writeRepository(root, {
        "server.py": [
          "from flask import Blueprint, Flask, redirect, request",
          "app = Flask(__name__)",
          'bp = Blueprint("redirects", __name__)',
          '@bp.get("/continue")',
          "def continue_to():",
          '    target = request.args.get("next", "")',
          '    destination = "/" + target',
          "    return redirect(destination, code=307)",
          'app.register_blueprint(bp, url_prefix="/links")',
          "",
        ].join("\n"),
      });

      const blueprintModels = models(await buildResidualRiskInventory(root));
      expect(blueprintModels).toHaveLength(1);
      expect(blueprintModels[0].propagators).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            kind: "flask-official-blueprint-factory",
          }),
          expect.objectContaining({ kind: "flask-blueprint-registration" }),
          expect.objectContaining({
            kind: "flask-blueprint-literal-url-prefix",
          }),
        ]),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("accepts the official nested Blueprint registration chain", async () => {
    const root = await mkdtemp(join(tmpdir(), "flask-nested-blueprint-"));
    try {
      await writeRepository(root, {
        "server.py": [
          "from flask import Blueprint, Flask, redirect, request",
          "app = Flask(__name__)",
          'parent = Blueprint("parent", __name__, url_prefix="/parent")',
          'child = Blueprint("child", __name__, url_prefix="/child")',
          '@child.get("/continue")',
          "def continue_to():",
          '    target = request.args.get("next", "")',
          '    destination = "/" + target',
          "    return redirect(destination, code=307)",
          "parent.register_blueprint(child)",
          "app.register_blueprint(parent)",
          "",
        ].join("\n"),
      });

      const blueprintModels = models(await buildResidualRiskInventory(root));
      expect(blueprintModels).toHaveLength(1);
      expect(blueprintModels[0].propagators).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            kind: "flask-blueprint-nesting",
            path: "server.py",
            line: 10,
          }),
          expect.objectContaining({
            kind: "flask-blueprint-registration",
            path: "server.py",
            line: 11,
          }),
        ]),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("accepts one literal prefix on a nested Blueprint edge", async () => {
    const root = await mkdtemp(join(tmpdir(), "flask-nested-prefix-"));
    try {
      await writeRepository(root, {
        "server.py": [
          "from flask import Blueprint, Flask, redirect, request",
          "app = Flask(__name__)",
          'parent = Blueprint("parent", __name__)',
          'child = Blueprint("child", __name__)',
          '@child.get("/continue")',
          "def continue_to():",
          '    target = request.args.get("next", "")',
          '    destination = "/" + target',
          "    return redirect(destination, code=307)",
          'parent.register_blueprint(child, url_prefix="/nested")',
          'app.register_blueprint(parent, url_prefix="/root")',
          "",
        ].join("\n"),
      });

      const blueprintModels = models(await buildResidualRiskInventory(root));
      expect(blueprintModels).toHaveLength(1);
      expect(blueprintModels[0].propagators).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            kind: "flask-blueprint-literal-url-prefix",
            line: 10,
            symbol: "/nested",
          }),
          expect.objectContaining({
            kind: "flask-blueprint-literal-url-prefix",
            line: 11,
            symbol: "/root",
          }),
        ]),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects ambiguous or unstable nested Blueprint chains", async () => {
    const registered = [
      "from flask import Blueprint, Flask, redirect, request",
      "app = Flask(__name__)",
      'parent = Blueprint("parent", __name__)',
      'child = Blueprint("child", __name__)',
      '@child.get("/continue")',
      "def continue_to():",
      '    target = request.args.get("next", "")',
      '    destination = "/" + target',
      "    return redirect(destination, code=307)",
      "parent.register_blueprint(child)",
      "app.register_blueprint(parent)",
      "",
    ].join("\n");
    const variants: ReadonlyArray<readonly [string, string]> = [
      [
        "unmounted-parent",
        registered.replace("app.register_blueprint(parent)\n", ""),
      ],
      [
        "non-blueprint-parent",
        registered.replace(
          'parent = Blueprint("parent", __name__)',
          "parent = object()",
        ),
      ],
      [
        "rebound-parent",
        registered.replace(
          "parent.register_blueprint(child)",
          "parent = object()\nparent.register_blueprint(child)",
        ),
      ],
      [
        "replaced-parent-member",
        registered.replace(
          "parent.register_blueprint(child)",
          "parent.register_blueprint = lambda value: None\nparent.register_blueprint(child)",
        ),
      ],
      [
        "dynamic-child",
        registered.replace(
          "parent.register_blueprint(child)",
          "parent.register_blueprint(load(child))",
        ),
      ],
      [
        "dynamic-nesting-prefix",
        registered.replace(
          "parent.register_blueprint(child)",
          "parent.register_blueprint(child, url_prefix=prefix)",
        ),
      ],
      [
        "unsupported-nesting-option",
        registered.replace(
          "parent.register_blueprint(child)",
          'parent.register_blueprint(child, subdomain="api")',
        ),
      ],
      [
        "conditional-nesting",
        registered.replace(
          "parent.register_blueprint(child)",
          "if enabled:\n    parent.register_blueprint(child)",
        ),
      ],
      [
        "multiple-child-mounts",
        registered.replace(
          "parent.register_blueprint(child)",
          "parent.register_blueprint(child)\nparent.register_blueprint(child)",
        ),
      ],
      [
        "rebound-application",
        registered.replace(
          "app.register_blueprint(parent)",
          "app = object()\napp.register_blueprint(parent)",
        ),
      ],
      [
        "replaced-application-member",
        registered.replace(
          "app.register_blueprint(parent)",
          "app.register_blueprint = lambda value: None\napp.register_blueprint(parent)",
        ),
      ],
      [
        "dynamic-parent-prefix",
        registered.replace(
          "app.register_blueprint(parent)",
          "app.register_blueprint(parent, url_prefix=prefix)",
        ),
      ],
      [
        "multiple-parent-mounts",
        registered.replace(
          "app.register_blueprint(parent)",
          "app.register_blueprint(parent)\napp.register_blueprint(parent)",
        ),
      ],
      [
        "parent-mounted-before-child",
        registered.replace(
          "parent.register_blueprint(child)\napp.register_blueprint(parent)",
          "app.register_blueprint(parent)\nparent.register_blueprint(child)",
        ),
      ],
      [
        "self-nesting",
        registered.replace(
          "parent.register_blueprint(child)\napp.register_blueprint(parent)",
          "child.register_blueprint(child)\napp.register_blueprint(child)",
        ),
      ],
      [
        "second-level-nesting",
        registered
          .replace(
            'parent = Blueprint("parent", __name__)',
            'grandparent = Blueprint("grandparent", __name__)\nparent = Blueprint("parent", __name__)',
          )
          .replace(
            "app.register_blueprint(parent)",
            "grandparent.register_blueprint(parent)\napp.register_blueprint(grandparent)",
          ),
      ],
    ];

    for (const [name, server] of variants) {
      const root = await mkdtemp(
        join(tmpdir(), `flask-nested-blueprint-negative-${name}-`),
      );
      try {
        await writeRepository(root, { "server.py": server });
        expect(
          models(await buildResidualRiskInventory(root)),
          name,
        ).toHaveLength(0);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  test("accepts the official cross-file Blueprint application-factory pattern", async () => {
    const root = await mkdtemp(join(tmpdir(), "flask-blueprint-factory-"));
    try {
      await writeRepository(root, {
        "service/__init__.py": [
          "from flask import Flask",
          "",
          "def create_app():",
          "    app = Flask(__name__)",
          "    from . import redirects",
          "    app.register_blueprint(redirects.bp)",
          "    return app",
          "",
        ].join("\n"),
        "service/redirects.py": [
          "from flask import Blueprint, redirect, request",
          'bp = Blueprint("redirects", __name__)',
          '@bp.get("/continue")',
          "def continue_to():",
          '    target = request.args.get("next", "")',
          '    destination = "/" + target',
          "    return redirect(destination, code=307)",
          "",
        ].join("\n"),
      });

      const blueprintModels = models(await buildResidualRiskInventory(root));
      expect(blueprintModels).toHaveLength(1);
      expect(blueprintModels[0].propagators).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            kind: "relative-python-blueprint-module-import",
            path: "service/__init__.py",
            line: 5,
          }),
          expect.objectContaining({
            kind: "flask-application-factory-return",
            path: "service/__init__.py",
            line: 7,
          }),
          expect.objectContaining({
            kind: "flask-blueprint-registration",
            path: "service/__init__.py",
            line: 6,
          }),
        ]),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("accepts exact relative Blueprint imports and literal URL prefixes", async () => {
    const blueprint = [
      "from flask import Blueprint, redirect, request",
      'bp = Blueprint("redirects", __name__)',
      '@bp.get("/continue")',
      "def continue_to():",
      '    target = request.args.get("next", "")',
      '    destination = "/" + target',
      "    return redirect(destination, code=307)",
      "",
    ].join("\n");
    const applications: ReadonlyArray<readonly [string, string, string]> = [
      [
        "module-level-symbol-alias",
        [
          "from flask import Flask",
          "from .redirects import bp as mounted",
          "app = Flask(__name__)",
          'app.register_blueprint(mounted, url_prefix="/links")',
          "",
        ].join("\n"),
        "relative-python-blueprint-symbol-import",
      ],
      [
        "factory-global-symbol",
        [
          "from flask import Flask",
          "from .redirects import bp",
          "",
          "def make_app(config=None):",
          "    app = Flask(__name__)",
          "    app.register_blueprint(bp)",
          "    return app",
          "",
        ].join("\n"),
        "flask-application-factory-return",
      ],
      [
        "factory-module-alias-prefix",
        [
          "from flask import Flask",
          "",
          "def create_app():",
          "    app = Flask(__name__)",
          "    from . import redirects as mounted",
          '    app.register_blueprint(mounted.bp, url_prefix="/links")',
          "    return app",
          "",
        ].join("\n"),
        "flask-blueprint-literal-url-prefix",
      ],
    ];

    for (const [name, application, expectedKind] of applications) {
      const root = await mkdtemp(
        join(tmpdir(), `flask-blueprint-import-positive-${name}-`),
      );
      try {
        await writeRepository(root, {
          "service/__init__.py": application,
          "service/redirects.py": blueprint,
        });
        const blueprintModels = models(await buildResidualRiskInventory(root));
        expect(blueprintModels, name).toHaveLength(1);
        expect(blueprintModels[0].propagators, name).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ kind: expectedKind }),
            expect.objectContaining({
              kind: "flask-blueprint-registration",
              path: "service/__init__.py",
            }),
          ]),
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  test("rejects ambiguous cross-file Blueprint reachability", async () => {
    const application = [
      "from flask import Flask",
      "",
      "def create_app():",
      "    app = Flask(__name__)",
      "    from . import redirects",
      "    app.register_blueprint(redirects.bp)",
      "    return app",
      "",
    ].join("\n");
    const blueprint = [
      "from flask import Blueprint, redirect, request",
      'bp = Blueprint("redirects", __name__)',
      '@bp.get("/continue")',
      "def continue_to():",
      '    target = request.args.get("next", "")',
      '    destination = "/" + target',
      "    return redirect(destination, code=307)",
      "",
    ].join("\n");
    const variants: ReadonlyArray<
      readonly [string, string, string, Record<string, string>?]
    > = [
      [
        "unregistered",
        application.replace("    app.register_blueprint(redirects.bp)\n", ""),
        blueprint,
      ],
      [
        "absolute-import",
        application.replace("from . import redirects", "import redirects"),
        blueprint,
      ],
      [
        "renamed-factory",
        application.replace("create_app", "build_app"),
        blueprint,
      ],
      [
        "decorated-factory",
        application.replace(
          "def create_app():",
          "@decorate\ndef create_app():",
        ),
        blueprint,
      ],
      [
        "missing-return",
        application.replace("    return app\n", ""),
        blueprint,
      ],
      [
        "wrong-return",
        application.replace("return app", "return object()"),
        blueprint,
      ],
      [
        "nested-registration",
        application.replace(
          "    app.register_blueprint(redirects.bp)",
          "    if enabled:\n        app.register_blueprint(redirects.bp)",
        ),
        blueprint,
      ],
      [
        "conditional-entire-factory-chain",
        application.replace(
          [
            "    app = Flask(__name__)",
            "    from . import redirects",
            "    app.register_blueprint(redirects.bp)",
            "    return app",
          ].join("\n"),
          [
            "    if enabled:",
            "        app = Flask(__name__)",
            "        from . import redirects",
            "        app.register_blueprint(redirects.bp)",
            "        return app",
          ].join("\n"),
        ),
        blueprint,
      ],
      [
        "rebound-module",
        application.replace(
          "    app.register_blueprint(redirects.bp)",
          "    redirects = object()\n    app.register_blueprint(redirects.bp)",
        ),
        blueprint,
      ],
      [
        "rebound-module-member",
        application.replace(
          "    app.register_blueprint(redirects.bp)",
          "    redirects.bp = object()\n    app.register_blueprint(redirects.bp)",
        ),
        blueprint,
      ],
      [
        "rebound-application",
        application.replace(
          "    app.register_blueprint(redirects.bp)",
          "    app = object()\n    app.register_blueprint(redirects.bp)",
        ),
        blueprint,
      ],
      [
        "replaced-registration-member",
        application.replace(
          "    app.register_blueprint(redirects.bp)",
          "    app.register_blueprint = lambda value: None\n    app.register_blueprint(redirects.bp)",
        ),
        blueprint,
      ],
      [
        "dynamic-prefix",
        application.replace(
          "register_blueprint(redirects.bp)",
          "register_blueprint(redirects.bp, url_prefix=prefix)",
        ),
        blueprint,
      ],
      [
        "unknown-option",
        application.replace(
          "register_blueprint(redirects.bp)",
          'register_blueprint(redirects.bp, subdomain="api")',
        ),
        blueprint,
      ],
      [
        "multiple-registration",
        application.replace(
          "    return app",
          "    app.register_blueprint(redirects.bp)\n    return app",
        ),
        blueprint,
      ],
      [
        "rebound-exported-blueprint",
        application,
        blueprint.replace(
          "    return redirect(destination, code=307)\n",
          "    return redirect(destination, code=307)\n\nbp = object()\n",
        ),
      ],
      [
        "different-relative-module",
        application.replace("from . import redirects", "from . import other"),
        blueprint,
        { "service/other.py": "bp = object()\n" },
      ],
    ];

    for (const [
      name,
      candidateApplication,
      candidateBlueprint,
      extra,
    ] of variants) {
      const root = await mkdtemp(
        join(tmpdir(), `flask-blueprint-import-negative-${name}-`),
      );
      try {
        await writeRepository(root, {
          "service/__init__.py": candidateApplication,
          "service/redirects.py": candidateBlueprint,
          ...extra,
        });
        expect(
          models(await buildResidualRiskInventory(root)),
          name,
        ).toHaveLength(0);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  test("rejects unproved or unstable Blueprint registration", async () => {
    const registered = [
      "from flask import Blueprint, Flask, redirect, request",
      "app = Flask(__name__)",
      'bp = Blueprint("redirects", __name__)',
      '@bp.get("/continue")',
      "def continue_to():",
      '    target = request.args.get("next", "")',
      '    destination = "/" + target',
      "    return redirect(destination, code=307)",
      "app.register_blueprint(bp)",
      "",
    ].join("\n");
    const variants: ReadonlyArray<readonly [string, string]> = [
      ["unregistered", registered.replace("app.register_blueprint(bp)\n", "")],
      [
        "dynamic-registration",
        registered.replace(
          "register_blueprint(bp)",
          "register_blueprint(load(bp))",
        ),
      ],
      [
        "dynamic-prefix",
        registered.replace(
          "register_blueprint(bp)",
          "register_blueprint(bp, url_prefix=prefix)",
        ),
      ],
      [
        "unsupported-option",
        registered.replace(
          "register_blueprint(bp)",
          'register_blueprint(bp, subdomain="api")',
        ),
      ],
      [
        "scoped-registration",
        registered.replace(
          "app.register_blueprint(bp)",
          "def mount():\n    app.register_blueprint(bp)",
        ),
      ],
      [
        "scoped-blueprint-factory",
        registered.replace(
          'bp = Blueprint("redirects", __name__)',
          'def build_blueprint():\n    bp = Blueprint("redirects", __name__)',
        ),
      ],
      [
        "rebound-blueprint",
        registered.replace(
          "app.register_blueprint(bp)",
          "bp = object()\napp.register_blueprint(bp)",
        ),
      ],
      [
        "rebound-application",
        registered.replace(
          "app.register_blueprint(bp)",
          "app = object()\napp.register_blueprint(bp)",
        ),
      ],
      [
        "replaced-registration-member",
        registered.replace(
          "app.register_blueprint(bp)",
          "app.register_blueprint = lambda value: None\napp.register_blueprint(bp)",
        ),
      ],
      [
        "multiple-registration",
        registered.replace(
          "app.register_blueprint(bp)",
          "app.register_blueprint(bp)\napp.register_blueprint(bp)",
        ),
      ],
      [
        "non-flask-application",
        registered.replace("app = Flask(__name__)", "app = Application()"),
      ],
    ];

    for (const [name, server] of variants) {
      const root = await mkdtemp(
        join(tmpdir(), `flask-blueprint-negative-${name}-`),
      );
      try {
        await writeRepository(root, { "server.py": server });
        expect(
          models(await buildResidualRiskInventory(root)),
          name,
        ).toHaveLength(0);
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
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

  test("teaches the reviewer the Flask mount, Location, and root-prefix boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"python-flask-open-redirect"}}',
    );
    expect(prompt).toContain("python-flask-open-redirect");
    expect(prompt).toContain("request.args");
    expect(prompt).toContain("request.form");
    expect(prompt).toContain('methods=["POST"]');
    expect(prompt).toContain("flask.Blueprint");
    expect(prompt).toContain("register_blueprint");
    expect(prompt).toContain("flask-blueprint-nesting");
    expect(prompt).toContain("child-to-parent");
    expect(prompt).toContain("relative-python-blueprint-module-import");
    expect(prompt).toContain("create_app");
    expect(prompt).toContain("url_prefix");
    expect(prompt).toContain("flask.redirect");
    expect(prompt).toContain("Location");
    expect(prompt).toContain("root-only");
    expect(prompt).toContain("follow_redirects=False");
    expect(prompt).toContain("CWE-601");
  });
});
