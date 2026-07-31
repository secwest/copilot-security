import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

const PUBLIC_ADDRESS = "93.184.216.34";
const METADATA_ADDRESS = "169.254.169.254";
const ATTACK_URL =
  "https://rebind.attacker.test/latest/meta-data/iam/security-credentials/preview-role";
const LEGITIMATE_URL = "https://preview.example.test/public/release-notes";

interface Resolver {
  calls: string[];
  resolveAll(hostname: string): Promise<string[]>;
}

interface RequestDetails {
  connectAddress: string;
  hostHeader: string;
  path: string;
  redirect: string;
  tlsServerName: string;
}

interface Transport {
  calls: RequestDetails[];
  request(details: RequestDetails): Promise<{ body: unknown }>;
}

interface HttpClient {
  get?(target: URL, options: { redirect: string }): Promise<{ body: unknown }>;
  getPinned?(
    target: URL,
    options: { connectAddress: string; redirect: string },
  ): Promise<{ body: unknown }>;
}

interface Fixture {
  createHttpClient(...dependencies: unknown[]): HttpClient;
  preview(
    request: { query: { url: string } },
    resolver: Resolver,
    httpClient: HttpClient,
  ): Promise<{ status: number; body: Record<string, unknown> }>;
}

test("DNS validation without connection pinning permits metadata SSRF", async () => {
  const vulnerable = await loadFixture("javascript-dns-rebinding-ssrf");
  const safe = await loadFixture("javascript-safe-pinned-dns-fetch");

  const vulnerableResolver = sequenceResolver([
    [PUBLIC_ADDRESS],
    [METADATA_ADDRESS],
  ]);
  const vulnerableTransport = recordingTransport();
  const vulnerableResult = await vulnerable.preview(
    requestFor(ATTACK_URL),
    vulnerableResolver,
    vulnerable.createHttpClient(vulnerableResolver, vulnerableTransport),
  );

  expect(vulnerableResult).toEqual({
    status: 200,
    body: {
      preview: {
        accessKeyId: "SYNTHETIC_METADATA_ACCESS_KEY",
        secretAccessKey: "SYNTHETIC_METADATA_SECRET",
      },
    },
  });
  expect(vulnerableResolver.calls).toEqual([
    "rebind.attacker.test",
    "rebind.attacker.test",
  ]);
  expect(vulnerableTransport.calls[0]).toMatchObject({
    connectAddress: METADATA_ADDRESS,
    hostHeader: "rebind.attacker.test",
    redirect: "error",
    tlsServerName: "rebind.attacker.test",
  });

  const safeResolver = sequenceResolver([[PUBLIC_ADDRESS], [METADATA_ADDRESS]]);
  const safeTransport = recordingTransport();
  const safeResult = await safe.preview(
    requestFor(ATTACK_URL),
    safeResolver,
    safe.createHttpClient(safeTransport),
  );

  expect(safeResult).toEqual({
    status: 200,
    body: { preview: { document: "public preview" } },
  });
  expect(safeResolver.calls).toEqual(["rebind.attacker.test"]);
  expect(safeTransport.calls[0]).toEqual({
    connectAddress: PUBLIC_ADDRESS,
    hostHeader: "rebind.attacker.test",
    path: "/latest/meta-data/iam/security-credentials/preview-role",
    redirect: "error",
    tlsServerName: "rebind.attacker.test",
  });

  for (const fixture of [vulnerable, safe]) {
    for (const answers of [
      [METADATA_ADDRESS],
      [PUBLIC_ADDRESS, METADATA_ADDRESS],
      ["::1"],
      [],
    ]) {
      const resolver = sequenceResolver([answers]);
      const transport = recordingTransport();
      const result = await fixture.preview(
        requestFor(ATTACK_URL),
        resolver,
        createClient(fixture, resolver, transport),
      );
      expect(result).toEqual({
        status: 403,
        body: { error: "destination_not_public" },
      });
      expect(transport.calls).toEqual([]);
    }

    const resolver = sequenceResolver([[PUBLIC_ADDRESS], [PUBLIC_ADDRESS]]);
    const transport = recordingTransport();
    expect(
      await fixture.preview(
        requestFor(LEGITIMATE_URL),
        resolver,
        createClient(fixture, resolver, transport),
      ),
    ).toEqual({
      status: 200,
      body: { preview: { document: "public preview" } },
    });
    expect(transport.calls[0]?.connectAddress).toBe(PUBLIC_ADDRESS);
  }

  const directTransport = recordingTransport();
  const safeClient = safe.createHttpClient(directTransport);
  await expect(
    safeClient.getPinned?.(new URL(ATTACK_URL), {
      connectAddress: METADATA_ADDRESS,
      redirect: "error",
    }),
  ).rejects.toThrow("validated public connection address");
  expect(directTransport.calls).toEqual([]);
});

function requestFor(url: string) {
  return { query: { url } };
}

function createClient(
  fixture: Fixture,
  resolver: Resolver,
  transport: Transport,
) {
  return fixture.createHttpClient.length === 2
    ? fixture.createHttpClient(resolver, transport)
    : fixture.createHttpClient(transport);
}

function sequenceResolver(answerSequence: string[][]): Resolver {
  const calls: string[] = [];
  return {
    calls,
    async resolveAll(hostname) {
      const index = Math.min(calls.length, answerSequence.length - 1);
      calls.push(hostname);
      return [...(answerSequence[index] ?? [])];
    },
  };
}

function recordingTransport(): Transport {
  const calls: RequestDetails[] = [];
  return {
    calls,
    async request(details) {
      calls.push({ ...details });
      if (details.connectAddress === METADATA_ADDRESS) {
        return {
          body: {
            accessKeyId: "SYNTHETIC_METADATA_ACCESS_KEY",
            secretAccessKey: "SYNTHETIC_METADATA_SECRET",
          },
        };
      }
      return { body: { document: "public preview" } };
    },
  };
}

async function loadFixture(fixture: string): Promise<Fixture> {
  const root = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    fixture,
    "src",
  );
  const preview = await import(pathToFileURL(resolve(root, "preview.js")).href);
  const httpClient = await import(
    pathToFileURL(resolve(root, "http-client.js")).href
  );
  return {
    createHttpClient: httpClient.createHttpClient,
    preview: preview.preview,
  } as Fixture;
}
