const MAX_QUERY_BYTES = 2048;
const MAX_PARAMETERS = 16;
const MAX_VALUE_CHARACTERS = 256;
const ALLOWED_PARAMETERS = new Set(["action", "recordId"]);

export function authorizeAndForward(
  rawQuery,
  principal,
  executeCanonicalRequest,
  state,
) {
  let parameters;
  try {
    parameters = parseCanonicalQuery(rawQuery);
  } catch {
    return { status: 400, executedAction: "rejected" };
  }

  if (parameters.action === "delete" && principal.role !== "administrator") {
    return { status: 403, executedAction: "denied" };
  }
  return executeCanonicalRequest(parameters, principal, state);
}

function parseCanonicalQuery(rawQuery) {
  if (
    typeof rawQuery !== "string" ||
    Buffer.byteLength(rawQuery, "utf8") > MAX_QUERY_BYTES
  ) {
    throw new Error("invalid query size");
  }
  const components = rawQuery === "" ? [] : rawQuery.split("&");
  if (components.length === 0 || components.length > MAX_PARAMETERS) {
    throw new Error("invalid parameter count");
  }

  const parameters = Object.create(null);
  for (const component of components) {
    const separator = component.indexOf("=");
    if (separator <= 0 || component.indexOf("=", separator + 1) !== -1) {
      throw new Error("non-canonical query component");
    }
    const name = decodeFormComponent(component.slice(0, separator));
    const value = decodeFormComponent(component.slice(separator + 1));
    if (!ALLOWED_PARAMETERS.has(name) || value.length > MAX_VALUE_CHARACTERS) {
      throw new Error("unknown or oversized parameter");
    }
    if (Object.hasOwn(parameters, name)) {
      throw new Error("duplicate decoded parameter rejected");
    }
    parameters[name] = value;
  }
  if (
    !Object.hasOwn(parameters, "action") ||
    !Object.hasOwn(parameters, "recordId")
  ) {
    throw new Error("missing required parameter");
  }
  return Object.freeze(parameters);
}

function decodeFormComponent(value) {
  if (/%(?![0-9a-f]{2})/iu.test(value)) {
    throw new Error("malformed percent encoding");
  }
  const decoded = decodeURIComponent(value.replace(/\+/gu, " "));
  if (/[^\u0020-\u007e]/u.test(decoded)) {
    throw new Error("non-ASCII query value rejected");
  }
  return decoded;
}
