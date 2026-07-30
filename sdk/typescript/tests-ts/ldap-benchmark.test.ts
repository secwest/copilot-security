import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { expect, test } from "bun:test";

interface DirectoryEntry {
  [attribute: string]: string | string[];
  dn: string;
}

type FilterNode =
  | { kind: "and"; children: FilterNode[] }
  | { kind: "or"; children: FilterNode[] }
  | { kind: "not"; child: FilterNode }
  | {
      kind: "assertion";
      attribute: string;
      value: Array<{ literal: string } | { wildcard: true }>;
    };

test("LDAP benchmark proves group-filter authorization bypass and RFC 4515 defense", async () => {
  const vulnerable = await loadFixture("javascript-ldap-filter-authorization");
  const safe = await loadFixture("javascript-safe-ldap-authorization");
  const groups: DirectoryEntry[] = [
    {
      dn: "cn=administrators,ou=groups,dc=example,dc=test",
      cn: "administrators",
      member: [
        "uid=admin,ou=users,dc=example,dc=test",
        "uid=star*user,ou=users,dc=example,dc=test",
      ],
    },
    {
      dn: "cn=readers,ou=groups,dc=example,dc=test",
      cn: "readers",
      member: "uid=viewer,ou=users,dc=example,dc=test",
    },
  ];
  const directory = directoryServer(groups);
  const injectedSubject = "*)(cn=administrators)(member=*";
  const attacker = {
    authenticated: true,
    directorySubject: injectedSubject,
    subject: "attacker@example.test",
    userId: "attacker",
  };

  expect(vulnerable.createSession(directory, attacker)).toEqual({
    subject: "attacker@example.test",
    role: "administrator",
    directoryGroup: "cn=administrators,ou=groups,dc=example,dc=test",
  });
  expect(directory.filters.at(-1)).toBe(
    "(&(member=*)(cn=administrators)(member=*)(cn=administrators))",
  );

  const accounts = accountDirectory(
    new Map([
      ["admin", "uid=admin,ou=users,dc=example,dc=test"],
      ["attacker", "uid=attacker,ou=users,dc=example,dc=test"],
      ["star", "uid=star*user,ou=users,dc=example,dc=test"],
      ["viewer", "uid=viewer,ou=users,dc=example,dc=test"],
    ]),
  );

  expect(safe.createSession(directory, accounts, attacker)).toBeNull();
  expect(directory.filters.at(-1)).toBe(
    "(&(member=uid=attacker,ou=users,dc=example,dc=test)(cn=administrators))",
  );

  const viewer = {
    ...attacker,
    directorySubject: "uid=admin,ou=users,dc=example,dc=test",
    subject: "viewer@example.test",
    userId: "viewer",
  };
  expect(safe.createSession(directory, accounts, viewer)).toBeNull();

  const administrator = {
    ...attacker,
    directorySubject: "ignored attacker-controlled value",
    subject: "admin@example.test",
    userId: "admin",
  };
  expect(safe.createSession(directory, accounts, administrator)).toEqual({
    subject: "admin@example.test",
    role: "administrator",
    directoryGroup: "cn=administrators,ou=groups,dc=example,dc=test",
  });

  const literalStarUser = {
    ...administrator,
    subject: "star@example.test",
    userId: "star",
  };
  expect(safe.createSession(directory, accounts, literalStarUser)).toEqual({
    subject: "star@example.test",
    role: "administrator",
    directoryGroup: "cn=administrators,ou=groups,dc=example,dc=test",
  });
  expect(directory.filters.at(-1)).toContain("uid=star\\2auser");
  expect(safe.escape(injectedSubject)).toBe(
    "\\2a\\29\\28cn=administrators\\29\\28member=\\2a",
  );
});

async function loadFixture(fixture: string): Promise<{
  createSession: (...arguments_: unknown[]) => unknown;
  escape: (value: string) => string;
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
  const authorization = (await import(
    pathToFileURL(resolve(sourceRoot, "authorization.js")).href
  )) as Record<string, unknown>;
  const session = (await import(
    pathToFileURL(resolve(sourceRoot, "session.js")).href
  )) as Record<string, unknown>;
  expect(typeof session["createAdministrativeSession"]).toBe("function");
  return {
    createSession: session["createAdministrativeSession"] as (
      ...arguments_: unknown[]
    ) => unknown,
    escape:
      typeof authorization["escapeLdapFilterAssertion"] === "function"
        ? (authorization["escapeLdapFilterAssertion"] as (
            value: string,
          ) => string)
        : (value) => value,
  };
}

function accountDirectory(principals: Map<string, string>) {
  return {
    principalDnForUser(userId: string): string | null {
      return principals.get(userId) ?? null;
    },
  };
}

function directoryServer(entries: DirectoryEntry[]) {
  const filters: string[] = [];
  return {
    filters,
    searchOne(filter: string): DirectoryEntry | null {
      filters.push(filter);
      const parsed = parseFilter(filter);
      return entries.find((entry) => matchesFilter(parsed, entry)) ?? null;
    },
  };
}

function parseFilter(filter: string): FilterNode {
  let index = 0;

  function parse(): FilterNode {
    if (filter[index++] !== "(") throw new Error("expected LDAP filter");
    const operator = filter[index];
    if (operator === "&" || operator === "|") {
      index += 1;
      const children: FilterNode[] = [];
      while (filter[index] === "(") children.push(parse());
      if (children.length === 0 || filter[index++] !== ")") {
        throw new Error("invalid LDAP boolean filter");
      }
      return { kind: operator === "&" ? "and" : "or", children };
    }
    if (operator === "!") {
      index += 1;
      const child = parse();
      if (filter[index++] !== ")") throw new Error("invalid LDAP not filter");
      return { kind: "not", child };
    }

    const equals = filter.indexOf("=", index);
    if (equals < index) throw new Error("invalid LDAP assertion");
    const attribute = filter.slice(index, equals).toLowerCase();
    index = equals + 1;
    const value: Array<{ literal: string } | { wildcard: true }> = [];
    let literal = "";
    while (index < filter.length && filter[index] !== ")") {
      if (filter[index] === "\\") {
        const hex = filter.slice(index + 1, index + 3);
        if (!/^[0-9a-f]{2}$/iu.test(hex)) {
          throw new Error("invalid LDAP hex escape");
        }
        literal += String.fromCharCode(Number.parseInt(hex, 16));
        index += 3;
      } else if (filter[index] === "*") {
        if (literal) value.push({ literal });
        literal = "";
        value.push({ wildcard: true });
        index += 1;
      } else {
        literal += filter[index++];
      }
    }
    if (literal) value.push({ literal });
    if (filter[index++] !== ")") throw new Error("unterminated LDAP assertion");
    return { kind: "assertion", attribute, value };
  }

  const parsed = parse();
  if (index !== filter.length) throw new Error("trailing LDAP filter data");
  return parsed;
}

function matchesFilter(filter: FilterNode, entry: DirectoryEntry): boolean {
  if (filter.kind === "and") {
    return filter.children.every((child) => matchesFilter(child, entry));
  }
  if (filter.kind === "or") {
    return filter.children.some((child) => matchesFilter(child, entry));
  }
  if (filter.kind === "not") return !matchesFilter(filter.child, entry);

  const raw = entry[filter.attribute];
  if (raw === undefined) return false;
  const values = Array.isArray(raw) ? raw : [raw];
  if (filter.value.length === 1 && "wildcard" in (filter.value[0] ?? {})) {
    return values.length > 0;
  }
  const expression = new RegExp(
    `^${filter.value
      .map((part) =>
        "wildcard" in part ? ".*" : escapeRegularExpression(part.literal),
      )
      .join("")}$`,
    "iu",
  );
  return values.some((value) => expression.test(value));
}

function escapeRegularExpression(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}
