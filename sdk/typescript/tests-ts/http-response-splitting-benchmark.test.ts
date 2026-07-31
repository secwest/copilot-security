import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";

interface Request {
  query: { filename?: string };
}

interface Delivery {
  status: number;
  headers: Map<string, string>;
  body: string;
}

interface Fixture {
  createReportApplication(publicReport: string): {
    handle(request: Request): string;
  };
  deliverThroughGateway(
    rawResponse: string,
    internalFiles: Map<string, string>,
  ): Delivery;
}

const PUBLIC_REPORT = "month,total\nJune,4200\n";
const INTERNAL_PATH = "/internal/tenant-alpine/signing-keys.csv";
const INTERNAL_EXPORT =
  "tenant,key_id,private_material\nalpine,key-7,alpine-private-signing-key\n";
const internalFiles = new Map([[INTERNAL_PATH, INTERNAL_EXPORT]]);

describe("HTTP response-splitting benchmark", () => {
  test("a CR/LF filename injects an internal redirect and discloses a protected export", async () => {
    const fixture = await loadFixture("javascript-http-response-splitting");
    const application = fixture.createReportApplication(PUBLIC_REPORT);

    const ordinary = deliver(fixture, application, "quarterly-report.csv");
    expect(ordinary.status).toBe(200);
    expect(ordinary.body).toBe(PUBLIC_REPORT);
    expect(ordinary.headers.has("x-accel-redirect")).toBe(false);

    const injectedFilename =
      `quarterly-report.csv"\r\nX-Accel-Redirect: ${INTERNAL_PATH}` +
      '\r\nX-Response-Split: "';
    const exposed = deliver(fixture, application, injectedFilename);

    expect(exposed.status).toBe(200);
    expect(exposed.headers.get("x-accel-redirect")).toBe(INTERNAL_PATH);
    expect(exposed.headers.get("x-response-split")).toBe('""');
    expect(exposed.body).toBe(INTERNAL_EXPORT);
    expect(exposed.body).toContain("alpine-private-signing-key");
  });

  test("control-byte rejection blocks splitting while legitimate names still work", async () => {
    const fixture = await loadFixture("javascript-safe-http-response-headers");
    const application = fixture.createReportApplication(PUBLIC_REPORT);
    const injectedFilename =
      `quarterly-report.csv"\r\nX-Accel-Redirect: ${INTERNAL_PATH}` +
      '\r\nX-Response-Split: "';

    const rejected = deliver(fixture, application, injectedFilename);
    expect(rejected.status).toBe(400);
    expect(rejected.headers.has("x-accel-redirect")).toBe(false);
    expect(rejected.body).toBe("invalid_filename");
    expect(rejected.body).not.toContain("alpine-private-signing-key");

    const legitimate = deliver(fixture, application, "résumé (final).csv");
    expect(legitimate.status).toBe(200);
    expect(legitimate.body).toBe(PUBLIC_REPORT);
    expect(legitimate.headers.get("content-disposition")).toContain(
      "filename*=UTF-8''r%C3%A9sum%C3%A9%20%28final%29.csv",
    );
  });
});

function deliver(
  fixture: Fixture,
  application: ReturnType<Fixture["createReportApplication"]>,
  filename: string,
): Delivery {
  return fixture.deliverThroughGateway(
    application.handle({ query: { filename } }),
    internalFiles,
  );
}

async function loadFixture(name: string): Promise<Fixture> {
  const source = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    name,
    "src",
    "download.js",
  );
  return (await import(pathToFileURL(source).href)) as Fixture;
}
