import { describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { scanQualityGatePrompt } from "../src/copilot-client.js";
import {
  buildFindingQualityGapInventory,
  buildResidualRiskInventory,
} from "../src/residual-risk.js";

const modelId = "python-django-open-redirect";
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

describe("Django open-redirect model", () => {
  test("keeps a strict executable exploit/control benchmark contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "python-django-open-redirect-manifest.json"),
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
      "python-django-open-redirect",
      "python-django-safe-local-redirect",
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

  test("keeps a strict class-view exploit/control benchmark contract", async () => {
    const manifest = JSON.parse(
      await readFile(
        join(
          benchmarkRoot,
          "python-django-class-view-open-redirect-manifest.json",
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
      "python-django-class-view-open-redirect",
      "python-django-class-view-safe-local-redirect",
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
    expect(manifest.cases[1].expected).toEqual([]);
  });

  test("separates the checked-in class-view exploit and fixed-local control", async () => {
    const exploit = join(
      benchmarkRoot,
      "fixtures",
      "python-django-class-view-open-redirect",
    );
    const control = join(
      benchmarkRoot,
      "fixtures",
      "python-django-class-view-safe-local-redirect",
    );
    const exploitModels = models(await buildResidualRiskInventory(exploit));
    const controlModels = models(await buildResidualRiskInventory(control));

    expect(exploitModels).toHaveLength(1);
    expect(exploitModels[0]).toMatchObject({
      source: {
        kind: "django-request-query-string",
        path: "src/views.py",
        line: 7,
      },
      sink: {
        kind: "django-shortcut-redirect-location",
        path: "src/views.py",
        line: 9,
        cweIds: ["CWE-601"],
      },
    });
    expect(exploitModels[0].propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "django-official-view-binding" }),
        expect.objectContaining({ kind: "django-class-based-view" }),
        expect.objectContaining({ kind: "django-as-view-registration" }),
        expect.objectContaining({ kind: "django-get-request-parameter" }),
      ]),
    );
    expect(controlModels).toHaveLength(0);
  });

  test("separates the checked-in root-prefix exploit and fixed-local control", async () => {
    const exploit = join(
      benchmarkRoot,
      "fixtures",
      "python-django-open-redirect",
    );
    const control = join(
      benchmarkRoot,
      "fixtures",
      "python-django-safe-local-redirect",
    );
    const exploitModels = models(await buildResidualRiskInventory(exploit));
    const controlModels = models(await buildResidualRiskInventory(control));

    expect(exploitModels).toHaveLength(1);
    expect(exploitModels[0]).toMatchObject({
      source: {
        kind: "django-request-query-string",
        path: "src/views.py",
        line: 5,
      },
      sink: {
        kind: "django-shortcut-redirect-location",
        path: "src/views.py",
        line: 7,
        cweIds: ["CWE-601"],
      },
    });
    expect(exploitModels[0].propagators).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "django-url-pattern" }),
        expect.objectContaining({ kind: "django-view-request-parameter" }),
        expect.objectContaining({ kind: "django-request-get-read" }),
        expect.objectContaining({ kind: "http-location-header-assignment" }),
      ]),
    );
    expect(controlModels).toHaveLength(0);
  });

  test("detects a registered function view whose root-only prefix can select another authority", async () => {
    const root = await mkdtemp(join(tmpdir(), "django-open-redirect-gap-"));
    try {
      await writeRepository(root, {
        "app/__init__.py": "",
        "app/views.py": [
          "from django.shortcuts import redirect",
          "",
          "def continue_to(request):",
          '    target = request.GET.get("next", "")',
          '    destination = "/" + target',
          "    return redirect(destination)",
          "",
        ].join("\n"),
        "app/urls.py": [
          "from django.urls import path",
          "from .views import continue_to",
          "",
          "urlpatterns = [",
          '    path("continue/", continue_to, name="continue"),',
          "]",
          "",
        ].join("\n"),
      });

      const detected = models(await buildResidualRiskInventory(root));
      expect(detected).toHaveLength(1);
      expect(detected[0]).toMatchObject({
        source: {
          kind: "django-request-query-string",
          path: "app/views.py",
          line: 4,
        },
        sink: {
          kind: "django-shortcut-redirect-location",
          path: "app/views.py",
          line: 6,
          cweIds: ["CWE-601"],
        },
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("detects a registered Django View get handler exposed through as_view", async () => {
    const root = await mkdtemp(join(tmpdir(), "django-class-view-gap-"));
    try {
      await writeRepository(root, {
        "app/__init__.py": "",
        "app/views.py": [
          "from django.shortcuts import redirect",
          "from django.views import View",
          "",
          "class ContinueView(View):",
          "    def get(self, request):",
          '        return redirect("/" + request.GET.get("next", ""))',
          "",
        ].join("\n"),
        "app/urls.py": [
          "from django.urls import path",
          "from .views import ContinueView",
          "",
          'urlpatterns = [path("continue/", ContinueView.as_view())]',
          "",
        ].join("\n"),
      });

      const detected = models(await buildResidualRiskInventory(root));
      expect(detected).toHaveLength(1);
      expect(detected[0]).toMatchObject({
        source: {
          kind: "django-request-query-string",
          path: "app/views.py",
          line: 6,
        },
        sink: {
          kind: "django-shortcut-redirect-location",
          path: "app/views.py",
          line: 6,
          cweIds: ["CWE-601"],
        },
      });
      expect(detected[0].propagators).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ kind: "django-official-view-binding" }),
          expect.objectContaining({ kind: "django-class-based-view" }),
          expect.objectContaining({ kind: "django-as-view-registration" }),
          expect.objectContaining({ kind: "django-get-request-parameter" }),
        ]),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("accepts qualified, relative-module, same-file, and async class-view forms", async () => {
    const variants: ReadonlyArray<
      readonly [string, Readonly<Record<string, string>>]
    > = [
      [
        "qualified-same-file",
        {
          "app.py": [
            "import django.views as django_views",
            "from django.shortcuts import redirect",
            "from django.urls import path",
            "",
            "class ContinueView(django_views.View):",
            "    def get(self, request, *args, **kwargs):",
            '        return redirect("/" + request.GET["next"])',
            "",
            'urlpatterns = [path("continue/", ContinueView.as_view())]',
            "",
          ].join("\n"),
        },
      ],
      [
        "relative-module-async",
        {
          "app/__init__.py": "",
          "app/views.py": [
            "from django.http import HttpResponseRedirect",
            "from django.views.generic import View as BaseView",
            "",
            "class ContinueView(BaseView):",
            "    async def get(self, request):",
            '        target = request.GET.get("next", "")',
            '        return HttpResponseRedirect("/" + target)',
            "",
          ].join("\n"),
          "app/urls.py": [
            "from django.urls import re_path",
            "from . import views",
            "",
            'urlpatterns = [re_path(r"^continue/$", views.ContinueView.as_view())]',
            "",
          ].join("\n"),
        },
      ],
    ];

    for (const [name, files] of variants) {
      const root = await mkdtemp(join(tmpdir(), `django-class-${name}-`));
      try {
        await writeRepository(root, files);
        const detected = models(await buildResidualRiskInventory(root));
        expect(detected, name).toHaveLength(1);
        expect(detected[0].propagators, name).toEqual(
          expect.arrayContaining([
            expect.objectContaining({ kind: "django-class-based-view" }),
            expect.objectContaining({ kind: "django-as-view-registration" }),
            expect.objectContaining({ kind: "django-get-request-parameter" }),
          ]),
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  test("suppresses a class-view redirect enclosed by the official host-and-scheme guard", async () => {
    const root = await mkdtemp(join(tmpdir(), "django-class-safe-guard-"));
    try {
      await writeRepository(root, {
        "app.py": [
          "from django.shortcuts import redirect",
          "from django.urls import path",
          "from django.utils.http import url_has_allowed_host_and_scheme",
          "from django.views import View",
          "",
          "class ContinueView(View):",
          "    def get(self, request):",
          '        target = request.GET.get("next", "")',
          "        if url_has_allowed_host_and_scheme(target, allowed_hosts=None):",
          "            return redirect(target)",
          '        return redirect("/")',
          "",
          'urlpatterns = [path("continue/", ContinueView.as_view())]',
          "",
        ].join("\n"),
      });
      expect(models(await buildResidualRiskInventory(root))).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("fails closed on ambiguous or unstable Django class-view dispatch", async () => {
    const baseViews = [
      "from django.shortcuts import redirect",
      "from django.views import View",
      "",
      "class ContinueView(View):",
      "    def get(self, request):",
      '        return redirect("/" + request.GET.get("next", ""))',
      "",
    ].join("\n");
    const baseUrls = [
      "from django.urls import path",
      "from .views import ContinueView",
      "",
      'urlpatterns = [path("continue/", ContinueView.as_view())]',
      "",
    ].join("\n");
    const variants: ReadonlyArray<
      readonly [string, string, string, Readonly<Record<string, string>>?]
    > = [
      [
        "unregistered",
        baseViews,
        baseUrls.replace("ContinueView.as_view()", "lambda request: request"),
      ],
      [
        "multiple-bases",
        baseViews.replace("(View)", "(View, object)"),
        baseUrls,
      ],
      [
        "wrong-base",
        baseViews.replace("from django.views import View", "class View: pass"),
        baseUrls,
      ],
      [
        "dispatch-override",
        baseViews.replace(
          "    def get",
          "    def dispatch(self, request):\n        return request\n\n    def get",
        ),
        baseUrls,
      ],
      [
        "setup-override",
        baseViews.replace(
          "    def get",
          "    def setup(self, request):\n        self.request = request\n\n    def get",
        ),
        baseUrls,
      ],
      [
        "decorated-get",
        baseViews.replace("    def get", "    @staticmethod\n    def get"),
        baseUrls,
      ],
      [
        "request-default",
        baseViews.replace("get(self, request)", "get(self, request=None)"),
        baseUrls,
      ],
      [
        "request-reassigned",
        baseViews.replace(
          "        return redirect",
          "        request = object()\n        return redirect",
        ),
        baseUrls,
      ],
      [
        "get-replaced",
        `${baseViews}ContinueView.get = lambda self, request: request\n`,
        baseUrls,
      ],
      ["class-rebound", `${baseViews}ContinueView = object\n`, baseUrls],
      [
        "as-view-keyword",
        baseViews,
        baseUrls.replace("as_view()", "as_view(mode='unsafe')"),
      ],
      [
        "as-view-replaced",
        baseViews,
        baseUrls.replace(
          "urlpatterns =",
          "ContinueView.as_view = lambda: None\nurlpatterns =",
        ),
      ],
      [
        "duplicate-class",
        `${baseViews}class ContinueView(View):\n    pass\n`,
        baseUrls,
      ],
      [
        "local-django-shadow",
        baseViews,
        baseUrls,
        {
          "django/__init__.py": "",
          "django/views.py": "class View: pass\n",
          "django/shortcuts.py": "def redirect(value): return value\n",
          "django/urls.py": "def path(route, view): return (route, view)\n",
        },
      ],
    ];

    for (const [name, views, urls, extra = {}] of variants) {
      const root = await mkdtemp(
        join(tmpdir(), `django-class-negative-${name}-`),
      );
      try {
        await writeRepository(root, {
          "app/__init__.py": "",
          "app/views.py": views,
          "app/urls.py": urls,
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

  test("accepts shortcut, response-class, qualified, named-target, subscript, and re_path forms", async () => {
    const variants: ReadonlyArray<
      readonly [string, Readonly<Record<string, string>>]
    > = [
      [
        "aliased-response-class",
        {
          "app.py": [
            "from django.http import HttpResponseRedirect as Jump",
            "from django.urls import re_path as register",
            "",
            "def continue_to(req):",
            '    return Jump(redirect_to="/" + req.GET["next"], preserve_request=True)',
            "",
            "urlpatterns = [",
            '    register("^continue/$", continue_to),',
            "]",
            "",
          ].join("\n"),
        },
      ],
      [
        "qualified-permanent-response",
        {
          "app.py": [
            "import django.http as responses",
            "import django.urls as routing",
            "",
            "def continue_to(request):",
            '    target = request.GET.get("next", "")',
            '    return responses.HttpResponsePermanentRedirect("/" + target)',
            "",
            'urlpatterns = [routing.path("continue/", continue_to)]',
            "",
          ].join("\n"),
        },
      ],
      [
        "named-shortcut-target",
        {
          "app.py": [
            "from django.shortcuts import redirect as go",
            "from django.urls import path",
            "",
            "def continue_to(request, tenant):",
            '    target = request.GET.get("next")',
            '    return go(to="/" + target, permanent=True)',
            "",
            "urlpatterns = [",
            '    path("tenant/<str:tenant>/", continue_to, name="continue"),',
            "]",
            "",
          ].join("\n"),
        },
      ],
    ];

    for (const [name, files] of variants) {
      const root = await mkdtemp(join(tmpdir(), `django-redirect-${name}-`));
      try {
        await writeRepository(root, files);
        const detected = models(await buildResidualRiskInventory(root));
        expect(detected, name).toHaveLength(1);
        expect(detected[0].sink.cweIds, name).toEqual(["CWE-601"]);
        expect(detected[0].propagators, name).toEqual(
          expect.arrayContaining([
            expect.objectContaining({
              kind: "django-official-url-pattern-binding",
            }),
            expect.objectContaining({ kind: "django-url-pattern" }),
            expect.objectContaining({ kind: "django-view-request-parameter" }),
            expect.objectContaining({ kind: "django-request-get-read" }),
            expect.objectContaining({
              kind: "django-official-redirect-binding",
            }),
            expect.objectContaining({
              kind: "http-location-header-assignment",
            }),
          ]),
        );
      } finally {
        await rm(root, { recursive: true, force: true });
      }
    }
  });

  test("preserves Django request control through a relative redirect wrapper", async () => {
    const root = await mkdtemp(join(tmpdir(), "django-redirect-wrapper-"));
    try {
      await writeRepository(root, {
        "app/__init__.py": "",
        "app/views.py": [
          "from .redirects import issue_redirect",
          "",
          "def continue_to(request):",
          '    target = request.GET.get("next", "")',
          '    return issue_redirect("/" + target)',
          "",
        ].join("\n"),
        "app/redirects.py": [
          "from django.shortcuts import redirect",
          "",
          "def issue_redirect(destination):",
          "    return redirect(destination)",
          "",
        ].join("\n"),
        "app/urls.py": [
          "from django.urls import path",
          "from . import views",
          "",
          'urlpatterns = [path("continue/", views.continue_to)]',
          "",
        ].join("\n"),
      });

      const detected = models(await buildResidualRiskInventory(root));
      expect(detected).toHaveLength(1);
      expect(detected[0].scope).toBe("cross-file-wrapper");
      expect(detected[0].source).toMatchObject({
        path: "app/views.py",
        line: 4,
      });
      expect(detected[0].sink).toMatchObject({
        path: "app/redirects.py",
        line: 4,
        cweIds: ["CWE-601"],
      });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("accepts a function view registered at more than one literal URL pattern", async () => {
    const root = await mkdtemp(join(tmpdir(), "django-redirect-multi-route-"));
    try {
      await writeRepository(root, {
        "app.py": [
          "from django.shortcuts import redirect",
          "from django.urls import path",
          "",
          "def continue_to(request):",
          '    return redirect("/" + request.GET.get("next", ""))',
          "",
          "urlpatterns = [",
          '    path("continue/", continue_to),',
          '    path("resume/", continue_to),',
          "]",
          "",
        ].join("\n"),
      });
      const detected = models(await buildResidualRiskInventory(root));
      expect(detected).toHaveLength(1);
      expect(
        detected[0].propagators.filter(
          ({ kind }: { kind: string }) => kind === "django-url-pattern",
        ),
      ).toHaveLength(2);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("suppresses an enclosing official host-and-scheme guard with a static host set", async () => {
    const root = await mkdtemp(join(tmpdir(), "django-redirect-safe-guard-"));
    try {
      await writeRepository(root, {
        "app.py": [
          "from django.shortcuts import redirect",
          "from django.urls import path",
          "from django.utils.http import url_has_allowed_host_and_scheme",
          "",
          "def continue_to(request):",
          '    target = request.GET.get("next", "")',
          '    destination = "/" + target',
          "    if url_has_allowed_host_and_scheme(destination, allowed_hosts=None):",
          "        return redirect(destination)",
          '    return redirect("/")',
          "",
          'urlpatterns = [path("continue/", continue_to)]',
          "",
        ].join("\n"),
      });
      expect(models(await buildResidualRiskInventory(root))).toHaveLength(0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("fails closed on unregistered, unstable, dynamic, opaque, and non-query Django boundaries", async () => {
    const views = [
      "from django.shortcuts import redirect",
      "",
      "def continue_to(request):",
      '    target = request.GET.get("next", "")',
      "    return redirect(target)",
      "",
      "def health(request):",
      '    return redirect("/")',
      "",
    ].join("\n");
    const urls = [
      "from django.urls import path",
      "from .views import continue_to",
      "",
      'urlpatterns = [path("continue/", continue_to)]',
      "",
    ].join("\n");
    const variants: ReadonlyArray<
      readonly [string, string, string, Readonly<Record<string, string>>?]
    > = [
      [
        "fixed-local-prefix",
        views.replace("redirect(target)", 'redirect("/continue/" + target)'),
        urls,
      ],
      [
        "request-post",
        views.replace(
          'request.GET.get("next", "")',
          'request.POST.get("next", "")',
        ),
        urls,
      ],
      ["unregistered-view", views, urls.replace("continue_to)]", "health)]")],
      [
        "dynamic-route",
        views,
        urls.replace('path("continue/",', "path(route_name,"),
      ],
      [
        "outside-urlpatterns",
        views,
        urls.replace(
          'urlpatterns = [path("continue/", continue_to)]',
          'path("continue/", continue_to)\nurlpatterns = []',
        ),
      ],
      [
        "rebound-view",
        views,
        urls.replace(
          "urlpatterns =",
          "continue_to = lambda request: request\nurlpatterns =",
        ),
      ],
      [
        "rebound-redirect",
        views.replace(
          "def continue_to(request):",
          "redirect = lambda value: value\n\ndef continue_to(request):",
        ),
        urls,
      ],
      [
        "opaque-transform",
        views.replace("redirect(target)", "redirect(sanitize(target))"),
        urls,
      ],
      [
        "unknown-redirect-keyword",
        views.replace("redirect(target)", "redirect(target, unexpected=True)"),
        urls,
      ],
      ["multiple-urlpatterns-assignments", views, `${urls}urlpatterns = []\n`],
      [
        "local-django-shadow",
        views,
        urls,
        {
          "django/__init__.py": "",
          "django/shortcuts.py": "def redirect(value): return value\n",
          "django/urls.py": "def path(route, view): return (route, view)\n",
        },
      ],
    ];

    for (const [name, candidateViews, candidateUrls, extra = {}] of variants) {
      const root = await mkdtemp(
        join(tmpdir(), `django-redirect-negative-${name}-`),
      );
      try {
        await writeRepository(root, {
          "app/__init__.py": "",
          "app/views.py": candidateViews,
          "app/urls.py": candidateUrls,
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

  test("requires Django registration, query, redirect, and origin evidence in review fields", async () => {
    const repository = join(
      benchmarkRoot,
      "fixtures",
      "python-django-open-redirect",
    );
    const inventory = await buildResidualRiskInventory(repository);
    const scanDirectory = await mkdtemp(
      join(tmpdir(), "django-redirect-quality-"),
    );
    const finding: any = {
      occurrenceId: "occ_django_redirect_quality",
      taxonomy: { cwe: ["CWE-601"] },
      locations: [
        { path: "src/views.py", startLine: 5, role: "source" },
        { path: "src/views.py", startLine: 7, role: "sink" },
      ],
      codeEvidence: [
        {
          id: "django-source",
          path: "src/views.py",
          startLine: 5,
          code: 'request.GET.get("next", "")',
          explanation: "Django request query field.",
          role: "source",
        },
        {
          id: "django-sink",
          path: "src/views.py",
          startLine: 7,
          code: "redirect(destination)",
          explanation: "Official Django redirect Location.",
          role: "sink",
        },
      ],
      validation: {
        summary: "A request value reaches a redirect.",
        method: "source review",
        evidence: ["django-source", "django-sink"],
      },
      attackPath: {
        summary: "A request value reaches a redirect.",
        dataflow: {
          source: "django-source",
          sink: "django-sink",
          outcome: "redirect",
        },
        evidenceRefs: ["django-source", "django-sink"],
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
        "A Django urlpatterns path registers the function view whose remote request.GET query field reaches django.shortcuts.redirect and its Location header. A root-only prefix can form a scheme-relative attacker-selected host; url_has_allowed_host_and_scheme, a fixed local prefix, or an exact same-origin allowlist is absent, producing a CWE-601 open redirect.";
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

  test("teaches the reviewer the Django Location and host-validation boundary", () => {
    const prompt = scanQualityGatePrompt(
      '{"frameworkModel":{"id":"python-django-open-redirect"}}',
    );
    expect(prompt).toContain("python-django-open-redirect");
    expect(prompt).toContain("urlpatterns");
    expect(prompt).toContain("View.as_view");
    expect(prompt).toContain("get(self, request");
    expect(prompt).toContain("request.GET");
    expect(prompt).toContain("django.shortcuts.redirect");
    expect(prompt).toContain("Location");
    expect(prompt).toContain("root-only");
    expect(prompt).toContain("url_has_allowed_host_and_scheme");
    expect(prompt).toContain("follow=False");
    expect(prompt).toContain("CWE-601");
  });
});
