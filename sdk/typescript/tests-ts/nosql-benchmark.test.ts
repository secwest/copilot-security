import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { expect, test } from "bun:test";

interface Account {
  id: string;
  username: string;
  loginVerifier: string;
  role: string;
}

interface LoginRequest {
  body: Record<string, unknown>;
  session: Record<string, unknown>;
}

interface LoginResponse {
  readonly statusCode: number;
  status(code: number): LoginResponse;
  end(): LoginResponse;
}

interface AccountDatabase {
  accounts: {
    findOne(query: Record<string, unknown>): Promise<Account | null>;
  };
}

type CreateSession = (
  request: LoginRequest,
  response: LoginResponse,
  database: AccountDatabase,
) => Promise<unknown>;

test("document-query benchmark proves operator authentication bypass and primitive rejection", async () => {
  const vulnerable = await loadCreateSession("javascript-nosql-auth-bypass");
  const safe = await loadCreateSession("javascript-safe-nosql-login");
  const attackBody = {
    username: { $ne: null },
    loginVerifier: { $ne: null },
  };
  const admin: Account = {
    id: "account-admin",
    username: "administrator",
    loginVerifier: "V".repeat(64),
    role: "administrator",
  };

  const vulnerableDatabase = documentDatabase([admin]);
  const vulnerableRequest: LoginRequest = {
    body: attackBody,
    session: {},
  };
  const vulnerableResponse = responseRecorder();
  await vulnerable(
    vulnerableRequest,
    vulnerableResponse,
    vulnerableDatabase.database,
  );

  expect(vulnerableDatabase.queries).toEqual([attackBody]);
  expect(vulnerableResponse.statusCode).toBe(204);
  expect(vulnerableRequest.session).toEqual({
    userId: "account-admin",
    role: "administrator",
  });

  const safeDatabase = documentDatabase([admin]);
  const safeRequest: LoginRequest = { body: attackBody, session: {} };
  const safeResponse = responseRecorder();
  await safe(safeRequest, safeResponse, safeDatabase.database);

  expect(safeDatabase.queries).toEqual([]);
  expect(safeResponse.statusCode).toBe(400);
  expect(safeRequest.session).toEqual({});
});

async function loadCreateSession(fixture: string): Promise<CreateSession> {
  const source = resolve(
    process.cwd(),
    "..",
    "..",
    "benchmarks",
    "fixtures",
    fixture,
    "src",
    "sessions.js",
  );
  const loaded = (await import(pathToFileURL(source).href)) as {
    createSession?: unknown;
  };
  expect(typeof loaded.createSession).toBe("function");
  return loaded.createSession as CreateSession;
}

function documentDatabase(records: Account[]): {
  database: AccountDatabase;
  queries: Array<Record<string, unknown>>;
} {
  const queries: Array<Record<string, unknown>> = [];
  return {
    queries,
    database: {
      accounts: {
        async findOne(query) {
          queries.push(query);
          return records.find((record) => matches(record, query)) ?? null;
        },
      },
    },
  };
}

function matches(record: Account, query: Record<string, unknown>): boolean {
  return Object.entries(query).every(([key, condition]) => {
    const actual = record[key as keyof Account];
    if (
      typeof condition === "object" &&
      condition !== null &&
      !Array.isArray(condition) &&
      "$ne" in condition
    ) {
      return actual !== (condition as { $ne: unknown }).$ne;
    }
    return actual === condition;
  });
}

function responseRecorder(): LoginResponse {
  let statusCode = 200;
  const response: LoginResponse = {
    get statusCode() {
      return statusCode;
    },
    status(code) {
      statusCode = code;
      return response;
    },
    end() {
      return response;
    },
  };
  return response;
}
