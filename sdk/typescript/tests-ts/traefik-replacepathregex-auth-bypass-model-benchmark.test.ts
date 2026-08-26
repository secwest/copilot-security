import { afterEach, describe, expect, test } from "bun:test";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

import { buildResidualRiskInventory } from "../src/residual-risk.js";
import { scanQualityGatePrompt } from "../src/copilot-client.js";

interface TraefikRecord {
  path: string;
  line: number;
  frameworkModel?: {
    id: string;
    source: { kind: string; path: string; line: number; symbol?: string };
    sink: { path: string; line: number; symbol?: string; cweIds: string[] };
    propagators: Array<{
      kind: string;
      path: string;
      line: number;
      symbol?: string;
    }>;
  };
}

const temporaryPaths: string[] = [];
const benchmarkRoot = resolve(process.cwd(), "..", "..", "benchmarks");

afterEach(async () => {
  await Promise.all(
    temporaryPaths.splice(0).map((path) => rm(path, { recursive: true })),
  );
});

function dynamicConfiguration(
  regex = "^/api(.*)",
  replacement = "/$1",
  publicMiddlewares = "[rewrite-api]",
  protectedMiddlewares = "[auth]",
  protectedService = "backend-svc",
  protectedEntryPoint = "web",
): string {
  return `http:
  routers:
    public-api:
      rule: "PathPrefix(\`/api\`)"
      entryPoints: [web]
      middlewares: ${publicMiddlewares}
      service: backend-svc
    protected-admin:
      rule: "PathPrefix(\`/admin\`)"
      entryPoints: [${protectedEntryPoint}]
      middlewares: ${protectedMiddlewares}
      service: ${protectedService}
  middlewares:
    rewrite-api:
      replacePathRegex:
        regex: "${regex}"
        replacement: "${replacement}"
    auth:
      basicAuth:
        users: ["admin:hash"]
  services:
    backend-svc:
      loadBalancer:
        servers:
          - url: "http://backend:3000"
`;
}

function compose(
  version = "3.7.6",
  command = "--providers.file.filename=/etc/traefik/dynamic.yml",
  volume = "./dynamic.yml:/etc/traefik/dynamic.yml:ro",
): string {
  return `services:
  proxy:
    image: traefik:v${version}
    command:
      - "${command}"
    volumes:
      - "${volume}"
`;
}

function dockerCompose({
  enable = "true",
  exposedByDefault = true,
  mapping = false,
  replacement = "/$$1",
  socket = true,
  version = "3.7.6",
}: {
  enable?: string | null;
  exposedByDefault?: boolean;
  mapping?: boolean;
  replacement?: string;
  socket?: boolean;
  version?: string;
} = {}): string {
  const labels = [
    ...(enable === null ? [] : [["traefik.enable", enable]]),
    ["traefik.http.routers.public-api.rule", "PathPrefix(`/api`)"],
    ["traefik.http.routers.public-api.entrypoints", "web"],
    ["traefik.http.routers.public-api.middlewares", "rewrite-api"],
    ["traefik.http.routers.public-api.service", "backend-svc"],
    ["traefik.http.routers.protected-admin.rule", "PathPrefix(`/admin`)"],
    ["traefik.http.routers.protected-admin.entrypoints", "web"],
    ["traefik.http.routers.protected-admin.middlewares", "auth"],
    ["traefik.http.routers.protected-admin.service", "backend-svc"],
    [
      "traefik.http.middlewares.rewrite-api.replacepathregex.regex",
      "^/api(.*)",
    ],
    [
      "traefik.http.middlewares.rewrite-api.replacepathregex.replacement",
      replacement,
    ],
    [
      "traefik.http.middlewares.auth.forwardauth.address",
      "http://auth:4181/verify",
    ],
    ["traefik.http.services.backend-svc.loadbalancer.server.port", "3000"],
  ];
  const labelLines = labels
    .map(([key, value]) =>
      mapping ? `      "${key}": "${value}"` : `      - "${key}=${value}"`,
    )
    .join("\n");
  return `services:
  proxy:
    image: traefik:v${version}
    command:
      - "--providers.docker=true"
${exposedByDefault ? "" : '      - "--providers.docker.exposedbydefault=false"\n'}    volumes:
${socket ? '      - "/var/run/docker.sock:/var/run/docker.sock:ro"\n' : '      - "./dynamic.yml:/dynamic.yml:ro"\n'}  backend:
    image: example/backend:1
    labels:
${labelLines}
`;
}

function records(inventory: string): TraefikRecord[] {
  return inventory
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line) as TraefikRecord)
    .filter(
      (record) =>
        record.frameworkModel?.id === "traefik-replacepathregex-auth-bypass",
    );
}

async function scan(
  dynamic = dynamicConfiguration(),
  composeSource = compose(),
  dynamicPath = "dynamic.yml",
  composePath = "compose.yml",
): Promise<TraefikRecord[]> {
  const root = await mkdtemp(join(tmpdir(), "copilot-security-traefik-"));
  temporaryPaths.push(root);
  const absoluteCompose = join(root, composePath);
  if (composePath.includes("/")) {
    await mkdir(dirname(absoluteCompose), { recursive: true });
  }
  await writeFile(absoluteCompose, composeSource);
  const absoluteDynamic = join(root, dynamicPath);
  if (dynamicPath.includes("/")) {
    await mkdir(dirname(absoluteDynamic), { recursive: true });
  }
  await writeFile(absoluteDynamic, dynamic);
  return records(await buildResidualRiskInventory(root));
}

describe("Traefik ReplacePathRegex authorization-bypass model", () => {
  test("keeps the real affected and repaired fixtures source-identical and under perfect gates", async () => {
    const affectedRoot = join(
      benchmarkRoot,
      "fixtures",
      "traefik-replacepathregex-auth-bypass",
    );
    const repairedRoot = join(
      benchmarkRoot,
      "fixtures",
      "traefik-replacepathregex-repaired",
    );
    const affectedCompose = await readFile(
      join(affectedRoot, "compose.yml"),
      "utf8",
    );
    const repairedCompose = await readFile(
      join(repairedRoot, "compose.yml"),
      "utf8",
    );
    expect(affectedCompose.replace("3.7.6", "3.7.7")).toBe(repairedCompose);
    for (const path of ["dynamic.yml", "src/witness.mjs"]) {
      expect(await readFile(join(affectedRoot, path), "utf8")).toBe(
        await readFile(join(repairedRoot, path), "utf8"),
      );
    }

    const affected = records(await buildResidualRiskInventory(affectedRoot));
    expect(affected).toHaveLength(1);
    expect(
      records(await buildResidualRiskInventory(repairedRoot)),
    ).toHaveLength(0);
    expect(affected[0]?.path).toBe("dynamic.yml");
    expect(affected[0]?.line).toBe(15);
    expect(affected[0]?.frameworkModel?.source.line).toBe(3);
    expect(affected[0]?.frameworkModel?.propagators.at(-1)?.line).toBe(3);

    const manifest = JSON.parse(
      await readFile(
        join(benchmarkRoot, "traefik-replacepathregex-manifest.json"),
        "utf8",
      ),
    ) as {
      thresholds: Record<string, number>;
      cases: Array<{ id: string; expected: unknown[] }>;
    };
    expect(manifest.cases.map(({ id }) => id)).toEqual([
      "traefik-replacepathregex-auth-bypass",
      "traefik-replacepathregex-repaired",
    ]);
    expect(manifest.cases[0]?.expected).toHaveLength(1);
    expect(manifest.cases[1]?.expected).toEqual([]);
    expect(manifest.thresholds["precision"]).toBe(1);
    expect(manifest.thresholds["recall"]).toBe(1);
    expect(manifest.thresholds["maxFalsePositives"]).toBe(0);
    expect(manifest.thresholds["maxFalseNegatives"]).toBe(0);
  });

  test("binds the public rewrite to an authenticated sibling on the same backend", async () => {
    const found = await scan();
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("dynamic.yml");
    expect(found[0]?.line).toBe(15);
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "public-traefik-prefix-router",
      path: "dynamic.yml",
      line: 3,
      symbol: "public-api",
    });
    expect(found[0]?.frameworkModel?.sink.cweIds).toEqual(["CWE-22"]);
    expect(found[0]?.frameworkModel?.propagators.at(-1)?.symbol).toBe(
      "traefik@3.7.6:compose-image-exact:replacepathregex-auth-bypass",
    );
    const decoyCompose = compose().replace(
      "  proxy:\n",
      "  decoy:\n    image: example/app:1\n  proxy:\n",
    );
    const withDecoy = await scan(undefined, decoyCompose);
    expect(withDecoy[0]?.frameworkModel?.propagators.at(-1)?.line).toBe(5);
  });

  test("enforces every official stable repair boundary", async () => {
    for (const version of [
      "2.0.0",
      "2.11.51",
      "3.6.0",
      "3.6.22",
      "3.7.0",
      "3.7.6",
    ]) {
      expect(await scan(undefined, compose(version))).toHaveLength(1);
    }
    for (const version of [
      "2.11.52",
      "3.0.0",
      "3.5.4",
      "3.6.23",
      "3.7.7",
      "3.8.0",
      "3.7.7-rc.1",
    ]) {
      expect(await scan(undefined, compose(version))).toHaveLength(0);
    }
  });

  test("requires the separator-free capture and exact traversal-producing replacement", async () => {
    expect(await scan(dynamicConfiguration("^/api/(.*)"))).toHaveLength(0);
    expect(
      await scan(dynamicConfiguration("^/api(.*)", "/api/$1")),
    ).toHaveLength(0);
    expect(await scan(dynamicConfiguration("^/other(.*)"))).toHaveLength(0);
  });

  test("requires a public rewrite and authenticated sibling on one service and entry point", async () => {
    expect(
      await scan(
        dynamicConfiguration(undefined, undefined, "[rewrite-api, auth]"),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        dynamicConfiguration(undefined, undefined, undefined, "[rewrite-api]"),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        dynamicConfiguration(
          undefined,
          undefined,
          undefined,
          undefined,
          "other",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        dynamicConfiguration(
          undefined,
          undefined,
          undefined,
          undefined,
          undefined,
          "admin",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        dynamicConfiguration().replace("    backend-svc:\n", "    other:\n"),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        dynamicConfiguration().replace(
          '        users: ["admin:hash"]',
          "        users: []",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        dynamicConfiguration().replace(
          '      basicAuth:\n        users: ["admin:hash"]',
          '      forwardAuth:\n        address: "http://auth:4181/verify"',
        ),
      ),
    ).toHaveLength(1);
  });

  test("requires an exact mounted file-provider path and official image", async () => {
    expect(
      await scan(
        undefined,
        compose(undefined, "--providers.file.filename=/other.yml"),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        undefined,
        compose(undefined, undefined, "./dynamic.yml:/etc/traefik/dynamic.yml"),
      ),
    ).toHaveLength(1);
    expect(
      await scan(
        undefined,
        compose(
          undefined,
          undefined,
          "./dynamic.yml:/etc/traefik/dynamic.yml:rw",
        ),
      ),
    ).toHaveLength(1);
    expect(
      await scan(
        undefined,
        compose().replace(
          '    command:\n      - "--providers.file.filename=/etc/traefik/dynamic.yml"\n',
          '    command: "--providers.file.filename=/etc/traefik/dynamic.yml"\n',
        ),
      ),
    ).toHaveLength(1);
    expect(
      await scan(
        undefined,
        compose().replace(
          '    volumes:\n      - "./dynamic.yml:/etc/traefik/dynamic.yml:ro"\n',
          "    volumes:\n      - type: bind\n        source: ./dynamic.yml\n        target: /etc/traefik/dynamic.yml\n        read_only: true\n",
        ),
      ),
    ).toHaveLength(1);
    expect(
      await scan(
        undefined,
        compose(
          undefined,
          undefined,
          "../dynamic.yml:/etc/traefik/dynamic.yml:ro",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        undefined,
        compose().replace("traefik:v3.7.6", "example/traefik:v3.7.6"),
      ),
    ).toHaveLength(0);
  });

  test("models the same authorization bypass through exact Docker provider labels", async () => {
    const found = await scan(undefined, dockerCompose());
    expect(found).toHaveLength(1);
    expect(found[0]?.path).toBe("compose.yml");
    expect(found[0]?.line).toBe(20);
    expect(found[0]?.frameworkModel?.source).toEqual({
      kind: "public-traefik-prefix-router",
      path: "compose.yml",
      line: 12,
      symbol: "public-api",
    });
    expect(found[0]?.frameworkModel?.propagators.at(-2)).toEqual({
      kind: "docker-provider-labeled-service",
      path: "compose.yml",
      line: 23,
      symbol: "backend",
    });
    expect(
      await scan(undefined, dockerCompose({ mapping: true })),
    ).toHaveLength(1);
    expect(
      await scan(
        undefined,
        dockerCompose({ mapping: true }).replaceAll("traefik.", "TRAEFIK."),
      ),
    ).toHaveLength(1);
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          '      - "/var/run/docker.sock:/var/run/docker.sock:ro"',
          "      - type: bind\n        source: /var/run/docker.sock\n        target: /var/run/docker.sock\n        read_only: true",
        ),
      ),
    ).toHaveLength(1);
    expect(
      await scan(
        undefined,
        dockerCompose({ enable: null, exposedByDefault: false }),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          "http://auth:4181/verify",
          "http://$AUTH_HOST:4181/verify",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(undefined, dockerCompose({ enable: "${ENABLE}" })),
    ).toHaveLength(0);
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          '      - "--providers.docker=true"',
          '      - "--providers.docker=true"\n      - "--providers.docker.constraints=Label(`tier`,`edge`)"',
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          '      - "--providers.docker=true"',
          '      - "--providers.docker=true"\n      - "--providers.docker.endpoint=tcp://docker:2375"',
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          "traefik.http.middlewares.auth.forwardauth.address=http://auth:4181/verify",
          "traefik.http.middlewares.auth.basicauth.usersfile=/run/secrets/users",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(undefined, dockerCompose({ exposedByDefault: false })),
    ).toHaveLength(1);
    expect(
      await scan(undefined, dockerCompose({ enable: "false" })),
    ).toHaveLength(0);
    expect(
      await scan(undefined, dockerCompose({ socket: false })),
    ).toHaveLength(0);
    expect(
      await scan(undefined, dockerCompose({ replacement: "/api/$$1" })),
    ).toHaveLength(0);
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          "traefik.http.middlewares.auth.forwardauth.address=http://auth:4181/verify",
          "traefik.http.middlewares.auth.forwardauth.address=${AUTH_URL}",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          "traefik.http.routers.public-api.middlewares=rewrite-api",
          "traefik.http.routers.public-api.middlewares=rewrite-api@docker",
        ),
      ),
    ).toHaveLength(1);
    expect(
      await scan(undefined, dockerCompose({ replacement: "/$${1}" })),
    ).toHaveLength(1);
    expect(
      await scan(undefined, dockerCompose({ replacement: "/$1" })),
    ).toHaveLength(1);
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          "traefik.http.services.backend-svc.loadbalancer.server.port=3000",
          "traefik.http.services.backend-svc.loadbalancer.server.port=70000",
        ),
      ),
    ).toHaveLength(0);
    expect(
      await scan(undefined, dockerCompose({ version: "3.5.4" })),
    ).toHaveLength(0);
    expect(
      await scan(undefined, dockerCompose({ version: "3.7.7" })),
    ).toHaveLength(0);
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          "traefik.http.routers.public-api.middlewares=rewrite-api",
          "traefik.http.routers.public-api.middlewares=rewrite-api@file",
        ),
      ),
    ).toHaveLength(0);
    const duplicateRegex =
      '      - "traefik.http.middlewares.rewrite-api.replacepathregex.regex=^/api(.*)"';
    expect(
      await scan(
        undefined,
        dockerCompose().replace(
          duplicateRegex,
          `${duplicateRegex}\n${duplicateRegex}`,
        ),
      ),
    ).toHaveLength(0);
  });

  test("resolves a nested mounted configuration without guessing another file", async () => {
    const nestedCompose = compose(
      undefined,
      undefined,
      "./config/dynamic.yml:/etc/traefik/dynamic.yml:ro",
    );
    expect(
      await scan(undefined, nestedCompose, "config/dynamic.yml"),
    ).toHaveLength(1);
    expect(await scan(undefined, nestedCompose)).toHaveLength(0);
  });

  test("excludes test, example, and vendor configuration trees", async () => {
    for (const directory of ["tests", "examples", "vendor"]) {
      const path = `${directory}/dynamic.yml`;
      expect(
        await scan(
          undefined,
          compose(
            undefined,
            undefined,
            `./${path}:/etc/traefik/dynamic.yml:ro`,
          ),
          path,
        ),
      ).toHaveLength(0);
    }
    expect(
      await scan(
        undefined,
        compose(),
        "examples/dynamic.yml",
        "examples/compose.yml",
      ),
    ).toHaveLength(0);
  });

  test("fails closed on duplicate-key and alias-based configuration", async () => {
    expect(
      await scan(`${dynamicConfiguration()}http:\n  routers: {}`),
    ).toHaveLength(0);
    expect(
      await scan(
        dynamicConfiguration()
          .replace("[rewrite-api]", "&m [rewrite-api]")
          .replace("[auth]", "*m"),
      ),
    ).toHaveLength(0);
  });

  test("requires a real loopback differential and bounded impact", () => {
    const prompt = scanQualityGatePrompt("");
    expect(prompt).toContain("traefik-replacepathregex-auth-bypass");
    expect(prompt).toContain("GHSA-cxjq-mrr5-89rv");
    expect(prompt).toContain("v3.6.0 through 3.6.22");
    expect(prompt).toContain("Docker provider");
    expect(prompt).toContain("exposedByDefault");
    expect(prompt).toContain("/api../protected");
    expect(prompt).toContain("loopback-only processes");
    expect(prompt).toContain("Report CWE-22");
    expect(prompt).toContain("never use a real credential");
  });
});
