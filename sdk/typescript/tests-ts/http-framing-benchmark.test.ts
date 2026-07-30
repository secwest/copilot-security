import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface BackendState {
  submissions: number;
  records: string[];
  adminDeletes: number;
}

interface CanonicalRequest {
  method: string;
  path: string;
  body: Buffer;
}

type VulnerableBackend = (rawRequests: Buffer, state: BackendState) => number;
type VulnerableGateway = (
  rawRequest: Buffer,
  backend: VulnerableBackend,
  state: BackendState,
) => number;
type SafeBackend = (request: CanonicalRequest, state: BackendState) => void;
type SafeGateway = (
  rawRequest: Buffer,
  principal: { role: string },
  backend: SafeBackend,
  state: BackendState,
) => number;

test("HTTP framing benchmark proves a hidden administrative request and rejects the same ambiguity", async () => {
  const vulnerable = await loadVulnerableFixture();
  const safe = await loadSafeFixture();
  const smuggledRequest = [
    "DELETE /admin/records HTTP/1.1",
    "Host: service.internal",
    "Content-Length: 0",
    "",
    "",
  ].join("\r\n");
  const conflictingBody = `0\r\n\r\n${smuggledRequest}`;
  const attack = requestBuffer(
    [
      "POST /submit HTTP/1.1",
      "Host: service.internal",
      `Content-Length: ${Buffer.byteLength(conflictingBody, "latin1")}`,
      "Transfer-Encoding: chunked",
      "",
      conflictingBody,
    ].join("\r\n"),
  );

  const vulnerableState = initialState();
  expect(vulnerable.gateway(attack, vulnerable.backend, vulnerableState)).toBe(
    2,
  );
  expect(vulnerableState).toEqual({
    submissions: 1,
    records: [],
    adminDeletes: 1,
  });

  const safeState = initialState();
  expect(() =>
    safe.gateway(attack, { role: "user" }, safe.backend, safeState),
  ).toThrow("conflicting Content-Length and Transfer-Encoding rejected");
  expect(safeState).toEqual(initialState());

  const ambiguousRequests = [
    {
      bytes: [
        "POST /submit HTTP/1.1",
        "Host: service.internal",
        "Content-Length: 0",
        "Content-Length: 0",
        "",
        "",
      ].join("\r\n"),
      error: "duplicate Content-Length rejected",
    },
    {
      bytes: [
        "POST /submit HTTP/1.1",
        "Host: service.internal",
        "Transfer-Encoding: chunked",
        "",
        "0",
        "",
        "",
      ].join("\r\n"),
      error: "unsupported Transfer-Encoding rejected",
    },
    {
      bytes: [
        "POST /submit HTTP/1.1",
        "Host: service.internal",
        "Content-Length: 00",
        "",
        "",
      ].join("\r\n"),
      error: "non-canonical Content-Length rejected",
    },
    {
      bytes: [
        "POST /submit HTTP/1.1",
        "Host: service.internal",
        "Content-Length: 0",
        "",
        "GET /other HTTP/1.1",
        "Host: service.internal",
        "",
        "",
      ].join("\r\n"),
      error: "request must contain exactly one complete message",
    },
  ];
  for (const ambiguous of ambiguousRequests) {
    const state = initialState();
    expect(() =>
      safe.gateway(
        requestBuffer(ambiguous.bytes),
        { role: "user" },
        safe.backend,
        state,
      ),
    ).toThrow(ambiguous.error);
    expect(state).toEqual(initialState());
  }

  const ordinarySubmission = requestBuffer(
    [
      "POST /submit HTTP/1.1",
      "Host: service.internal",
      "Content-Length: 5",
      "",
      "hello",
    ].join("\r\n"),
  );
  expect(
    safe.gateway(ordinarySubmission, { role: "user" }, safe.backend, safeState),
  ).toBe(202);
  expect(safeState.submissions).toBe(1);

  const administrativeRequest = requestBuffer(
    [
      "DELETE /admin/records HTTP/1.1",
      "Host: service.internal",
      "Content-Length: 0",
      "",
      "",
    ].join("\r\n"),
  );
  expect(
    safe.gateway(
      administrativeRequest,
      { role: "user" },
      safe.backend,
      safeState,
    ),
  ).toBe(403);
  expect(safeState.adminDeletes).toBe(0);
  expect(safeState.records).toEqual(["invoice-1", "invoice-2"]);

  expect(
    safe.gateway(
      administrativeRequest,
      { role: "administrator" },
      safe.backend,
      safeState,
    ),
  ).toBe(202);
  expect(safeState.adminDeletes).toBe(1);
  expect(safeState.records).toEqual([]);
});

async function loadVulnerableFixture(): Promise<{
  gateway: VulnerableGateway;
  backend: VulnerableBackend;
}> {
  const fixture = await loadFixture("javascript-http-request-smuggling");
  expect(typeof fixture.gateway["authorizeAndForward"]).toBe("function");
  expect(typeof fixture.backend["processBackendPipeline"]).toBe("function");
  return {
    gateway: fixture.gateway["authorizeAndForward"] as VulnerableGateway,
    backend: fixture.backend["processBackendPipeline"] as VulnerableBackend,
  };
}

async function loadSafeFixture(): Promise<{
  gateway: SafeGateway;
  backend: SafeBackend;
}> {
  const fixture = await loadFixture("javascript-safe-http-framing");
  expect(typeof fixture.gateway["authorizeAndForward"]).toBe("function");
  expect(typeof fixture.backend["processCanonicalRequest"]).toBe("function");
  return {
    gateway: fixture.gateway["authorizeAndForward"] as SafeGateway,
    backend: fixture.backend["processCanonicalRequest"] as SafeBackend,
  };
}

async function loadFixture(fixture: string): Promise<{
  gateway: Record<string, unknown>;
  backend: Record<string, unknown>;
}> {
  const sourceRoot = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    fixture,
    "src",
  );
  return {
    gateway: (await import(
      pathToFileURL(resolve(sourceRoot, "gateway.js")).href
    )) as Record<string, unknown>,
    backend: (await import(
      pathToFileURL(resolve(sourceRoot, "backend.js")).href
    )) as Record<string, unknown>,
  };
}

function requestBuffer(request: string): Buffer {
  return Buffer.from(request, "latin1");
}

function initialState(): BackendState {
  return {
    submissions: 0,
    records: ["invoice-1", "invoice-2"],
    adminDeletes: 0,
  };
}
