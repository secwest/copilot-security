const ACCOUNT_PATH = "/users/user[";
const ATTRIBUTES = new Set(["passwordVerifier", "role", "username"]);
const DEFAULT_USERS = Object.freeze([
  Object.freeze({
    username: "administrator",
    passwordVerifier: "admin-proof",
    role: "administrator",
  }),
  Object.freeze({
    username: "viewer",
    passwordVerifier: "viewer-proof",
    role: "viewer",
  }),
]);

export function createXmlAccountDirectory(users = DEFAULT_USERS) {
  const entries = users.map((user) => Object.freeze({ ...user }));
  const queries = [];
  return Object.freeze({
    queries,
    selectOne(expression, variables = {}) {
      queries.push(
        Object.freeze({
          expression,
          variables: Object.freeze({ ...variables }),
        }),
      );
      const predicate = parseAccountExpression(expression);
      return (
        entries.find((entry) => evaluate(predicate, entry, variables)) ?? null
      );
    },
  });
}

function parseAccountExpression(expression) {
  if (
    typeof expression !== "string" ||
    expression.length > 2_048 ||
    !expression.startsWith(ACCOUNT_PATH) ||
    !expression.endsWith("]")
  ) {
    throw new TypeError("unsupported XPath account expression");
  }
  const tokens = tokenize(expression.slice(ACCOUNT_PATH.length, -1));
  let index = 0;

  function parseOr() {
    let node = parseAnd();
    while (tokens[index]?.kind === "or") {
      index += 1;
      node = Object.freeze({ kind: "or", left: node, right: parseAnd() });
    }
    return node;
  }

  function parseAnd() {
    let node = parsePrimary();
    while (tokens[index]?.kind === "and") {
      index += 1;
      node = Object.freeze({ kind: "and", left: node, right: parsePrimary() });
    }
    return node;
  }

  function parsePrimary() {
    if (tokens[index]?.kind === "left") {
      index += 1;
      const node = parseOr();
      if (tokens[index++]?.kind !== "right") {
        throw new TypeError("unterminated XPath predicate group");
      }
      return node;
    }
    const left = parseValue();
    if (tokens[index++]?.kind !== "equals") {
      throw new TypeError("expected XPath equality");
    }
    return Object.freeze({ kind: "equals", left, right: parseValue() });
  }

  function parseValue() {
    const token = tokens[index++];
    if (
      token?.kind !== "attribute" &&
      token?.kind !== "literal" &&
      token?.kind !== "variable"
    ) {
      throw new TypeError("expected XPath predicate value");
    }
    return token;
  }

  const parsed = parseOr();
  if (index !== tokens.length) {
    throw new TypeError("trailing XPath predicate data");
  }
  return parsed;
}

function tokenize(predicate) {
  const tokens = [];
  let index = 0;
  const token =
    /\s*(?:(and|or)\b|([A-Za-z_][\w.-]*)\/text\(\)|\$([A-Za-z_][\w.-]*)|'([^']*)'|([=()]))/gy;
  while (index < predicate.length) {
    token.lastIndex = index;
    const match = token.exec(predicate);
    if (!match || match.index !== index) {
      throw new TypeError("unsupported XPath predicate syntax");
    }
    if (match[1]) tokens.push(Object.freeze({ kind: match[1] }));
    else if (match[2]) {
      if (!ATTRIBUTES.has(match[2])) {
        throw new TypeError("unsupported XPath account attribute");
      }
      tokens.push(Object.freeze({ kind: "attribute", name: match[2] }));
    } else if (match[3]) {
      tokens.push(Object.freeze({ kind: "variable", name: match[3] }));
    } else if (match[4] !== undefined) {
      tokens.push(Object.freeze({ kind: "literal", value: match[4] }));
    } else {
      const punctuation = { "(": "left", ")": "right", "=": "equals" };
      tokens.push(Object.freeze({ kind: punctuation[match[5]] }));
    }
    index = token.lastIndex;
  }
  return tokens;
}

function evaluate(predicate, entry, variables) {
  if (predicate.kind === "and") {
    return (
      evaluate(predicate.left, entry, variables) &&
      evaluate(predicate.right, entry, variables)
    );
  }
  if (predicate.kind === "or") {
    return (
      evaluate(predicate.left, entry, variables) ||
      evaluate(predicate.right, entry, variables)
    );
  }
  return (
    value(predicate.left, entry, variables) ===
    value(predicate.right, entry, variables)
  );
}

function value(operand, entry, variables) {
  if (operand.kind === "literal") return operand.value;
  if (operand.kind === "variable") return variables[operand.name] ?? "";
  return entry[operand.name] ?? "";
}
