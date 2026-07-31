import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, test } from "bun:test";
import { PLUGIN_ROOT } from "./plugin-root.js";

const repositoryRoot = join(PLUGIN_ROOT, "..", "..", "..");

type Principal = { id: string; role: "administrator" | "viewer" };
type State = {
  records: Set<string>;
  audit: Array<{ action: string; principalId: string; recordId: string }>;
};
type Result = {
  status: number;
  authorizedAction?: string;
  executedAction?: string;
};
type Backend = (
  request: string | Readonly<Record<string, string>>,
  principal: Principal,
  state: State,
) => Result;
type Gateway = (
  rawQuery: string,
  principal: Principal,
  backend: Backend,
  state: State,
) => Result;

const viewer: Principal = { id: "viewer-7", role: "viewer" };
const administrator: Principal = {
  id: "administrator-1",
  role: "administrator",
};
const recordId = "shared-report";

function createState(): State {
  return { records: new Set([recordId]), audit: [] };
}

async function fixture(
  name: string,
): Promise<{ gateway: Gateway; backend: Backend }> {
  const sourceRoot = join(
    repositoryRoot,
    "benchmarks",
    "fixtures",
    name,
    "src",
  );
  const gatewayModule = (await import(
    pathToFileURL(join(sourceRoot, "gateway.js")).href
  )) as Record<string, unknown>;
  const backendModule = (await import(
    pathToFileURL(join(sourceRoot, "backend.js")).href
  )) as Record<string, unknown>;
  return {
    gateway: gatewayModule["authorizeAndForward"] as Gateway,
    backend: (backendModule["executeBackend"] ??
      backendModule["executeCanonicalRequest"]) as Backend,
  };
}

describe("duplicate query-parameter authorization benchmark", () => {
  test("first-value authorization and last-value execution delete a protected record", async () => {
    const vulnerable = await fixture(
      "javascript-duplicate-parameter-authorization-bypass",
    );
    const state = createState();

    const result = vulnerable.gateway(
      `action=view&recordId=${recordId}&action=delete`,
      viewer,
      vulnerable.backend,
      state,
    );

    expect(result).toEqual({ status: 200, executedAction: "delete" });
    expect(state.records.has(recordId)).toBe(false);
    expect(state.audit).toEqual([
      { action: "delete", principalId: viewer.id, recordId },
    ]);
  });

  test("the vulnerable gateway denies the same values when the privileged value is first", async () => {
    const vulnerable = await fixture(
      "javascript-duplicate-parameter-authorization-bypass",
    );
    const state = createState();

    const result = vulnerable.gateway(
      `action=delete&recordId=${recordId}&action=view`,
      viewer,
      vulnerable.backend,
      state,
    );

    expect(result).toEqual({ status: 403, authorizedAction: "delete" });
    expect(state.records.has(recordId)).toBe(true);
    expect(state.audit).toEqual([]);
  });

  test("the safe gateway rejects literal and encoded duplicate decoded names", async () => {
    const safe = await fixture("javascript-safe-canonical-query-authorization");
    const state = createState();

    expect(
      safe.gateway(
        `action=view&recordId=${recordId}&action=delete`,
        viewer,
        safe.backend,
        state,
      ),
    ).toEqual({ status: 400, executedAction: "rejected" });
    expect(
      safe.gateway(
        `action=view&recordId=${recordId}&act%69on=delete`,
        viewer,
        safe.backend,
        state,
      ),
    ).toEqual({ status: 400, executedAction: "rejected" });
    expect(state.records.has(recordId)).toBe(true);
    expect(state.audit).toEqual([]);
  });

  test("the safe path authorizes and executes the same canonical action", async () => {
    const safe = await fixture("javascript-safe-canonical-query-authorization");
    const state = createState();

    expect(
      safe.gateway(
        `action=view&recordId=${recordId}`,
        viewer,
        safe.backend,
        state,
      ),
    ).toEqual({ status: 200, executedAction: "view" });
    expect(
      safe.gateway(
        `action=delete&recordId=${recordId}`,
        viewer,
        safe.backend,
        state,
      ),
    ).toEqual({ status: 403, executedAction: "denied" });
    expect(state.records.has(recordId)).toBe(true);

    expect(
      safe.gateway(
        `action=delete&recordId=${recordId}`,
        administrator,
        safe.backend,
        state,
      ),
    ).toEqual({ status: 200, executedAction: "delete" });
    expect(state.records.has(recordId)).toBe(false);
    expect(state.audit).toEqual([
      { action: "delete", principalId: administrator.id, recordId },
    ]);
  });

  test("the safe parser fails closed on malformed and oversized query inputs", async () => {
    const safe = await fixture("javascript-safe-canonical-query-authorization");
    const state = createState();

    expect(
      safe.gateway(
        `action=view&recordId=${recordId}&unknown=x`,
        viewer,
        safe.backend,
        state,
      ).status,
    ).toBe(400);
    expect(
      safe.gateway(
        `action=view&recordId=${recordId}%`,
        viewer,
        safe.backend,
        state,
      ).status,
    ).toBe(400);
    expect(
      safe.gateway(
        `action=view&recordId=${"x".repeat(2048)}`,
        viewer,
        safe.backend,
        state,
      ).status,
    ).toBe(400);
    expect(state.records.has(recordId)).toBe(true);
    expect(state.audit).toEqual([]);
  });
});
