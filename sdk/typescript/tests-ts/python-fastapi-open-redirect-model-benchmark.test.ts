import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const modelId = "python-fastapi-open-redirect";

async function writeRepository(
  root: string,
  files: Readonly<Record<string, string>>,
): Promise<void> {
  for (const [path, contents] of Object.entries(files)) {
    const absolute = join(root, path);
    await mkdir(join(absolute, ".."), { recursive: true });
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

function directServer(
  declaration: string,
  destination = "next_url",
  imports: readonly string[] = [
    "from typing import Annotated",
    "from fastapi import FastAPI, Query",
    "from fastapi.responses import RedirectResponse",
  ],
  setup: readonly string[] = [],
): string {
  return [
    ...imports,
    "app = FastAPI()",
    ...setup,
    '@app.get("/login")',
    `def login(${declaration}) -> RedirectResponse:`,
    `    destination = ${destination}`,
    "    return RedirectResponse(url=destination, status_code=307)",
    "",
  ].join("\n");
}

describe("FastAPI open-redirect model", () => {
  test("keeps a strict executable exploit/control benchmark contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-fastapi-open-redirect-manifest.json"),
        "utf8",
      ),
    );

    expect(manifest.schemaVersion).toBe("1.0");
    expect(Object.values(manifest.thresholds)).toEqual(
      expect.arrayContaining([0, 1]),
    );
    expect(
      Object.values(manifest.thresholds).every(
        (value) => value === 0 || value === 1,
      ),
    ).toBeTrue();
    expect(manifest.cases.map(({ id }: { id: string }) => id)).toEqual([
      "python-fastapi-open-redirect",
      "python-fastapi-safe-local-redirect",
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

  test("separates the executable absolute-origin exploit and local-prefix control", async () => {
    const exploit = join(
      benchmarkRoot,
      "fixtures",
      "python-fastapi-open-redirect",
    );
    const control = join(
      benchmarkRoot,
      "fixtures",
      "python-fastapi-safe-local-redirect",
    );
    const exploitModels = models(await buildResidualRiskInventory(exploit));
    const controlModels = models(await buildResidualRiskInventory(control));

    expect(exploitModels).toHaveLength(1);
    expect(exploitModels[0].scope).toBe("cross-file-wrapper");
    expect(exploitModels[0].source.kind).toBe(
      "fastapi-request-string-parameter",
    );
    expect(exploitModels[0].sink).toEqual({
      kind: "fastapi-redirect-response-location",
      path: "src/redirects.py",
      line: 5,
      cweIds: ["CWE-601"],
    });
    expect(exploitModels[0].propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "fastapi-redirect-route" }),
        expect.objectContaining({
          kind: "fastapi-official-query-parameter",
        }),
        expect.objectContaining({
          kind: "fastapi-official-redirect-response-binding",
        }),
        expect.objectContaining({ kind: "http-location-header-assignment" }),
      ]),
    );
    expect(controlModels).toHaveLength(0);
  });

  test("accepts inferred, aliased Annotated, legacy Query, and Starlette response bindings", async () => {
    const variants: ReadonlyArray<readonly [string, string]> = [
      [
        "inferred",
        directServer("next_url: str", "next_url", [
          "from fastapi import FastAPI",
          "from fastapi.responses import RedirectResponse",
        ]),
      ],
      [
        "aliased-annotated",
        [
          "import typing as types",
          "import fastapi as api",
          "import fastapi.params as params",
          "import starlette.responses as responses",
          "app = api.APIRouter()",
          '@app.head("/login")',
          "def login(next_url: types.Annotated[str, params.Query()]):",
          "    return responses.RedirectResponse(url=next_url)",
          "",
        ].join("\n"),
      ],
      [
        "legacy-alias",
        [
          "from fastapi import APIRouter, Query as RequestQuery",
          "from fastapi.responses import RedirectResponse as RedirectResponse",
          "router = APIRouter()",
          '@router.post("/login")',
          "def login(next_url: str = RequestQuery()):",
          "    return RedirectResponse(next_url)",
          "",
        ].join("\n"),
      ],
    ];

    for (const [name, server] of variants) {
      const root = await mkdtemp(join(tmpdir(), `fastapi-redirect-${name}-`));
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

  test("preserves exact request control through relative and multi-hop wrappers", async () => {
    const relative = await mkdtemp(
      join(tmpdir(), "fastapi-redirect-relative-"),
    );
    const multiHop = await mkdtemp(
      join(tmpdir(), "fastapi-redirect-multihop-"),
    );
    const server = [
      "from typing import Annotated",
      "from fastapi import FastAPI, Query",
      "from .redirects import issue_redirect",
      "app = FastAPI()",
      '@app.get("/login")',
      "def login(next_url: Annotated[str, Query()]):",
      "    return issue_redirect(next_url)",
      "",
    ].join("\n");
    const redirects = [
      "from fastapi.responses import RedirectResponse",
      "def issue_redirect(destination):",
      "    return RedirectResponse(url=destination)",
      "",
    ].join("\n");
    try {
      await writeRepository(relative, {
        "src/__init__.py": "",
        "src/server.py": server,
        "src/redirects.py": redirects,
      });
      const relativeModels = models(await buildResidualRiskInventory(relative));
      expect(relativeModels).toHaveLength(1);
      expect(relativeModels[0].scope).toBe("cross-file-wrapper");
      expect(relativeModels[0].propagators).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "relative-python-import" }),
          expect.objectContaining({ kind: "wrapper-call-argument" }),
          expect.objectContaining({ kind: "wrapper-parameter" }),
        ]),
      );
      await writeFile(
        join(relative, "src", "server.py"),
        server.replace(
          "    return issue_redirect(next_url)",
          [
            '    destination = "/continue?next=" + next_url',
            "    return issue_redirect(destination)",
          ].join("\n"),
        ),
        "utf8",
      );
      expect(models(await buildResidualRiskInventory(relative))).toHaveLength(
        0,
      );

      await writeRepository(multiHop, {
        "src/__init__.py": "",
        "src/server.py": server.replace(
          "from .redirects import issue_redirect",
          "from .gateway import issue_redirect",
        ),
        "src/gateway.py": [
          "from .service import continue_redirect",
          "def issue_redirect(destination):",
          "    return continue_redirect(destination)",
          "",
        ].join("\n"),
        "src/service.py": [
          "from .redirects import render_redirect",
          "def continue_redirect(destination):",
          "    return render_redirect(destination)",
          "",
        ].join("\n"),
        "src/redirects.py": redirects.replace(
          /issue_redirect/gu,
          "render_redirect",
        ),
      });
      const multiHopModels = models(await buildResidualRiskInventory(multiHop));
      expect(multiHopModels).toHaveLength(1);
      expect(multiHopModels[0].scope).toBe("cross-file-multi-hop-wrapper");
      expect(
        multiHopModels[0].propagators.filter(
          (candidate: any) => candidate.kind === "wrapper-parameter",
        ),
      ).toHaveLength(3);
      await writeFile(
        join(multiHop, "src", "server.py"),
        server
          .replace(
            "from .redirects import issue_redirect",
            "from .gateway import issue_redirect",
          )
          .replace(
            "    return issue_redirect(next_url)",
            [
              '    destination = "/continue?next=" + next_url',
              "    return issue_redirect(destination)",
            ].join("\n"),
          ),
        "utf8",
      );
      expect(models(await buildResidualRiskInventory(multiHop))).toHaveLength(
        0,
      );
    } finally {
      await rm(relative, { recursive: true, force: true });
      await rm(multiHop, { recursive: true, force: true });
    }
  });

  test("fails closed on unsupported metadata, unstable bindings, shadows, and ambiguous URL calls", async () => {
    const variants: ReadonlyArray<
      readonly [string, string, Readonly<Record<string, string>>?]
    > = [
      [
        "configured-query",
        directServer("next_url: Annotated[str, Query(min_length=1)]"),
      ],
      [
        "extra-metadata",
        directServer('next_url: Annotated[str, Query(), "tag"]'),
      ],
      ["non-string", directServer("next_url: int")],
      [
        "missing-query-import",
        directServer("next_url: Annotated[str, Query()]", "next_url", [
          "from typing import Annotated",
          "from fastapi import FastAPI",
          "from fastapi.responses import RedirectResponse",
          "def Query(): return object()",
        ]),
      ],
      [
        "rebound-query",
        directServer(
          "next_url: Annotated[str, Query()]",
          "next_url",
          undefined,
          ["Query = lambda: object()"],
        ),
      ],
      [
        "local-fastapi-shadow",
        directServer("next_url: Annotated[str, Query()]"),
        { "fastapi.py": "class FastAPI: pass\n" },
      ],
      [
        "local-starlette-shadow",
        [
          "from fastapi import FastAPI",
          "from starlette.responses import RedirectResponse",
          "app = FastAPI()",
          '@app.get("/login")',
          "def login(next_url: str):",
          "    return RedirectResponse(next_url)",
          "",
        ].join("\n"),
        {
          "starlette/__init__.py": "",
          "starlette/responses.py": "class RedirectResponse: pass\n",
        },
      ],
      [
        "rebound-response",
        directServer("next_url: str", "next_url", undefined, [
          "RedirectResponse = lambda *args, **kwargs: None",
        ]),
      ],
      [
        "parameter-reassigned",
        directServer("next_url: str", '"https://fixed.invalid/"', undefined, [
          "",
        ]).replace(
          '    destination = "https://fixed.invalid/"',
          '    next_url = "https://fixed.invalid/"\n    destination = next_url',
        ),
      ],
      [
        "multiple-controlled-parameters",
        directServer("next_url: str, fallback: str", "next_url + fallback", [
          "from fastapi import FastAPI",
          "from fastapi.responses import RedirectResponse",
        ]),
      ],
      [
        "positional-and-named-url",
        directServer("next_url: str").replace(
          "RedirectResponse(url=destination, status_code=307)",
          "RedirectResponse(destination, url=next_url)",
        ),
      ],
      [
        "expanded-keywords",
        directServer("next_url: str").replace(
          "RedirectResponse(url=destination, status_code=307)",
          'RedirectResponse(**{"url": destination})',
        ),
      ],
      [
        "lookalike-response",
        [
          "from fastapi import FastAPI",
          "def RedirectResponse(url): return url",
          "app = FastAPI()",
          '@app.get("/login")',
          "def login(next_url: str):",
          "    return RedirectResponse(next_url)",
          "",
        ].join("\n"),
      ],
    ];

    for (const [name, server, extra = {}] of variants) {
      const root = await mkdtemp(
        join(tmpdir(), `fastapi-redirect-negative-${name}-`),
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

  test("does not misclassify a root-only prefix as local-origin confinement", async () => {
    const root = await mkdtemp(join(tmpdir(), "fastapi-redirect-root-prefix-"));
    try {
      await writeRepository(root, {
        "server.py": directServer("next_url: str", '"/" + next_url', [
          "from fastapi import FastAPI",
          "from fastapi.responses import RedirectResponse",
        ]),
      });
      expect(models(await buildResidualRiskInventory(root))).toHaveLength(1);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("requires redirect-boundary and origin-control evidence in review fields", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "python-fastapi-open-redirect",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "fastapi-redirect-quality-"),
    );
    const finding: any = {
      occurrenceId: "occ_fastapi_redirect_quality",
      taxonomy: { cwe: ["CWE-601"] },
      locations: [
        { path: "src/server.py", startLine: 11, role: "source" },
        { path: "src/redirects.py", startLine: 5, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "redirect-source",
          path: "src/server.py",
          startLine: 11,
          code: "next_url: Annotated[str, Query()]",
          explanation: "FastAPI request parameter.",
          role: "source",
        },
        {
          id: "redirect-sink",
          path: "src/redirects.py",
          startLine: 5,
          code: "RedirectResponse(url=destination)",
          explanation: "HTTP Location response.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A request value reaches a redirect.",
        method: "source review",
        evidence: ["redirect-source", "redirect-sink"],
      },
      attackPath: {
        summary: "A request value reaches a redirect.",
        dataflow: {
          source: "redirect-source",
          sink: "redirect-sink",
          outcome: "redirect",
        },
        evidenceRefs: ["redirect-source", "redirect-sink"],
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
        "The official FastAPI GET path operation binds a remote query parameter and sends it through RedirectResponse into the Location header. An absolute URL lets the attacker select an origin and host; no same-origin allowlist, fixed local prefix, or url_has_allowed_host check prevents the open redirect under CWE-601.";
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

  test("teaches the reviewer the exact Location and local-prefix boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"python-fastapi-open-redirect"}}',
    );
    expect(prompt).toContain("python-fastapi-open-redirect");
    expect(prompt).toContain("RedirectResponse");
    expect(prompt).toContain("Location");
    expect(prompt).toContain("fixed local");
    expect(prompt).toContain("CWE-601");
  });
});
