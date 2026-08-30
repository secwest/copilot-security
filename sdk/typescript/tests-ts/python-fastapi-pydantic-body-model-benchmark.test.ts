import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");
const sourceKind = '"kind":"fastapi-pydantic-body-field"';

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

function crossFileRepository(
  models = [
    "from typing import ClassVar",
    "from pydantic import BaseModel",
    "class ReportRequest(BaseModel):",
    "    name: str",
    '    fixed_command: ClassVar[str] = "status"',
    "",
  ].join("\n"),
  server = [
    "from fastapi import FastAPI",
    "from .models import ReportRequest",
    "from .runner import run_report",
    "app = FastAPI()",
    '@app.post("/report")',
    "def report(payload: ReportRequest):",
    "    return run_report(payload.name)",
    "",
  ].join("\n"),
  extra: Readonly<Record<string, string>> = {},
): Readonly<Record<string, string>> {
  return {
    "src/__init__.py": "",
    "src/models.py": models,
    "src/runner.py": [
      "import subprocess",
      "def run_report(report_name):",
      '    return subprocess.run(f"printf report:{report_name}", shell=True, check=True, timeout=2)',
      "",
    ].join("\n"),
    "src/server.py": server,
    ...extra,
  };
}

describe("FastAPI Pydantic request-body field model", () => {
  test("detects direct and exact relative-import body-field flows", async () => {
    const sameFile = await mkdtemp(join(tmpdir(), "fastapi-pydantic-same-"));
    const relative = await mkdtemp(
      join(tmpdir(), "fastapi-pydantic-relative-"),
    );
    try {
      await writeRepository(sameFile, {
        "server.py": [
          "import subprocess",
          "from fastapi import FastAPI",
          "from pydantic import BaseModel",
          "class ReportRequest(BaseModel):",
          "    name: str",
          "app = FastAPI()",
          '@app.put("/report")',
          "def report(payload: ReportRequest):",
          '    return subprocess.run(f"printf report:{payload.name}", shell=True, check=True, timeout=2)',
          "",
        ].join("\n"),
      });
      const sameInventory = await buildResidualRiskInventory(sameFile);
      expect(sameInventory).toContain(sourceKind);
      expect(sameInventory).toContain('"scope":"same-file"');
      expect(sameInventory).toContain(
        '"kind":"fastapi-pydantic-body-field-read"',
      );

      await writeRepository(
        relative,
        crossFileRepository(
          [
            "import typing as types",
            "import pydantic as schema",
            "class ReportRequest(schema.BaseModel):",
            "    name: str | None",
            '    fixed_command: types.ClassVar[str] = "status"',
            "",
          ].join("\n"),
          [
            "import fastapi as api",
            "from .models import ReportRequest as Payload",
            "from .runner import run_report",
            "router = api.APIRouter()",
            '@router.patch("/report")',
            "def report(payload: Payload):",
            '    return run_report(getattr(payload, "name"))',
            "",
          ].join("\n"),
        ),
      );
      const relativeInventory = await buildResidualRiskInventory(relative);
      expect(relativeInventory).toContain(sourceKind);
      expect(relativeInventory).toContain('"scope":"cross-file-wrapper"');
      expect(relativeInventory).toContain(
        '"kind":"relative-python-pydantic-model-import"',
      );
      expect(relativeInventory).toContain(
        '"kind":"pydantic-request-body-string-field"',
      );
    } finally {
      await rm(sameFile, { recursive: true, force: true });
      await rm(relative, { recursive: true, force: true });
    }
  });

  test("preserves the exact body field through bounded Python relays", async () => {
    const root = await mkdtemp(join(tmpdir(), "fastapi-pydantic-multihop-"));
    try {
      await writeRepository(root, {
        ...crossFileRepository(),
        "src/server.py": [
          "from fastapi import FastAPI",
          "from .models import ReportRequest",
          "from .gateway import route_report",
          "app = FastAPI()",
          '@app.delete("/report")',
          "def report(payload: ReportRequest):",
          "    return route_report(payload.name)",
          "",
        ].join("\n"),
        "src/gateway.py": [
          "from .service import dispatch_report",
          "def route_report(report_name):",
          "    return dispatch_report(report_name)",
          "",
        ].join("\n"),
        "src/service.py": [
          "from .runner import run_report",
          "def dispatch_report(report_name):",
          "    return run_report(report_name)",
          "",
        ].join("\n"),
      });
      const inventory = await buildResidualRiskInventory(root);
      expect(inventory).toContain(sourceKind);
      expect(inventory).toContain('"scope":"cross-file-multi-hop-wrapper"');
      expect(inventory).toContain(
        '"kind":"wrapper-parameter","path":"src/gateway.py"',
      );
      expect(inventory).toContain('"kind":"fastapi-pydantic-body-field-read"');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("rejects ambiguous framework, model, parameter, and field semantics", async () => {
    const exactModels = crossFileRepository()["src/models.py"]!;
    const exactServer = crossFileRepository()["src/server.py"]!;
    const sixtyFiveFields = [
      "from pydantic import BaseModel",
      "class ReportRequest(BaseModel):",
      ...Array.from({ length: 65 }, (_, index) => `    value_${index}: str`),
      "",
    ].join("\n");
    const cases: ReadonlyArray<
      readonly [string, string, string, Readonly<Record<string, string>>?]
    > = [
      [
        "no-route",
        exactModels,
        exactServer.replace('@app.post("/report")\n', ""),
      ],
      ["get-route", exactModels, exactServer.replace("@app.post", "@app.get")],
      [
        "arbitrary-class",
        exactModels
          .replace("from pydantic import BaseModel\n", "")
          .replace("(BaseModel)", ""),
        exactServer,
      ],
      [
        "multiple-inheritance",
        exactModels.replace("(BaseModel)", "(BaseModel, object)"),
        exactServer,
      ],
      [
        "model-method",
        `${exactModels.trimEnd()}\n    def normalize(self):\n        return self.name\n`,
        exactServer,
      ],
      [
        "model-config",
        exactModels.replace(
          "    name: str",
          '    model_config = {"strict": True}\n    name: str',
        ),
        exactServer,
      ],
      [
        "dynamic-field",
        exactModels
          .replace("    name: str", '    name: str = Field(pattern=".*")')
          .replace(
            "from pydantic import BaseModel",
            "from pydantic import BaseModel, Field",
          ),
        exactServer,
      ],
      [
        "integer-field",
        exactModels.replace("name: str", "name: int"),
        exactServer,
      ],
      [
        "classvar-selected",
        exactModels,
        exactServer.replace("payload.name", "payload.fixed_command"),
      ],
      [
        "default-parameter",
        exactModels,
        exactServer.replace(
          "payload: ReportRequest",
          "payload: ReportRequest = None",
        ),
      ],
      [
        "annotated-parameter",
        exactModels,
        exactServer
          .replace(
            "from fastapi import FastAPI",
            "from typing import Annotated\nfrom fastapi import FastAPI",
          )
          .replace(
            "payload: ReportRequest",
            "payload: Annotated[ReportRequest, Body()]",
          ),
      ],
      [
        "parameter-reassignment",
        exactModels,
        exactServer.replace(
          "    return run_report",
          '    payload = ReportRequest(name="fixed")\n    return run_report',
        ),
      ],
      [
        "field-mutation",
        exactModels,
        exactServer.replace(
          "    return run_report",
          '    payload.name = "fixed"\n    return run_report',
        ),
      ],
      [
        "whole-model-alias",
        exactModels,
        exactServer.replace(
          "    return run_report(payload.name)",
          "    copy = payload\n    return run_report(copy.name)",
        ),
      ],
      [
        "dynamic-getattr",
        exactModels,
        exactServer.replace(
          "    return run_report(payload.name)",
          '    field = "name"\n    return run_report(getattr(payload, field))',
        ),
      ],
      [
        "multiple-fields",
        exactModels.replace("    name: str", "    name: str\n    suffix: str"),
        exactServer.replace("payload.name", "payload.name + payload.suffix"),
      ],
      [
        "factory-replacement",
        exactModels,
        exactServer.replace(
          '@app.post("/report")',
          'app = replacement\n@app.post("/report")',
        ),
      ],
      [
        "basemodel-replacement",
        `${exactModels.trimEnd()}\nBaseModel = replacement\n`,
        exactServer,
      ],
      [
        "resource-cap",
        sixtyFiveFields,
        exactServer.replace("payload.name", "payload.value_0"),
      ],
      [
        "local-fastapi-shadow",
        exactModels,
        exactServer,
        { "fastapi.py": "class FastAPI:\n    pass\n" },
      ],
      [
        "local-pydantic-shadow",
        exactModels,
        exactServer,
        { "pydantic.py": "class BaseModel:\n    pass\n" },
      ],
      [
        "local-typing-shadow",
        exactModels,
        exactServer,
        { "typing.py": "class ClassVar:\n    pass\n" },
      ],
    ];

    for (const [name, models, server, extra = {}] of cases) {
      const root = await mkdtemp(join(tmpdir(), `fastapi-pydantic-${name}-`));
      try {
        await writeRepository(root, crossFileRepository(models, server, extra));
        expect(await buildResidualRiskInventory(root), name).not.toContain(
          sourceKind,
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  test("requires route, model, field, and stability proof in review fields", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "python-fastapi-pydantic-body-command-injection",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "fastapi-pydantic-quality-"),
    );
    const finding: any = {
      occurrenceId: "occ_fastapi_pydantic_quality",
      taxonomy: { cwe: ["CWE-78"] },
      locations: [
        { path: "src/server.py", startLine: 10, role: "source" },
        { path: "src/runner.py", startLine: 5, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "body-source",
          path: "src/server.py",
          startLine: 10,
          code: "payload.name",
          explanation: "Body field read.",
          role: "source",
        },
        {
          id: "shell-sink",
          path: "src/runner.py",
          startLine: 5,
          code: "subprocess.run(..., shell=True)",
          explanation: "Shell grammar sink.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A request reaches a shell.",
        method: "source review",
        evidence: ["body-source", "shell-sink"],
      },
      attackPath: {
        summary: "A request reaches a shell.",
        dataflow: {
          source: "body-source",
          sink: "shell-sink",
          outcome: "shell grammar",
        },
        evidenceRefs: ["body-source", "shell-sink"],
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
        "The official FastAPI request body route binds a Pydantic BaseModel request body. The exact declared string field payload.name is read from a stable Pydantic request parameter, crosses the relative wrapper, and reaches subprocess with shell=True as shell grammar for CWE-78. There is no model or parameter escape and no ClassVar, mutation, or validator broadening.";
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

  test("teaches review to preserve the exact Pydantic body boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"python-web-command","propagators":[{"kind":"fastapi-pydantic-body-field-read"}]}}',
    );
    expect(prompt).toContain("fastapi-pydantic-body-field-read");
    expect(prompt).toContain(
      "Pydantic validation proves type/schema acceptance, not shell safety",
    );
    expect(prompt).toContain("ClassVar");
    expect(prompt).toContain("official FastAPI request-body route");
  });
});
