const MAX_HEADER_BYTES = 16 * 1024;
const MAX_BODY_BYTES = 64 * 1024;

export function authorizeAndForward(
  rawRequest,
  principal,
  processCanonicalRequest,
  state,
) {
  const request = parseCanonicalRequest(rawRequest);
  if (
    request.path.startsWith("/admin/") &&
    principal.role !== "administrator"
  ) {
    return 403;
  }
  processCanonicalRequest(request, state);
  return 202;
}

function parseCanonicalRequest(rawRequest) {
  const headerEnd = rawRequest.indexOf("\r\n\r\n");
  if (headerEnd < 0 || headerEnd > MAX_HEADER_BYTES) {
    throw new Error("invalid request headers");
  }
  const lines = rawRequest
    .subarray(0, headerEnd)
    .toString("latin1")
    .split("\r\n");
  const [method, path, version] = lines.shift().split(" ");
  if (version !== "HTTP/1.1" || !method || !path) {
    throw new Error("invalid request line");
  }
  const headers = new Map();
  for (const line of lines) {
    if (/^[ \t]/u.test(line))
      throw new Error("obsolete folded header rejected");
    const separator = line.indexOf(":");
    if (separator <= 0) throw new Error("invalid header");
    const name = line.slice(0, separator).toLowerCase();
    const value = line.slice(separator + 1).trim();
    const values = headers.get(name) ?? [];
    values.push(value);
    headers.set(name, values);
  }
  const contentLengths = headers.get("content-length") ?? [];
  const transferEncodings = headers.get("transfer-encoding") ?? [];
  if (contentLengths.length > 0 && transferEncodings.length > 0) {
    throw new Error(
      "conflicting Content-Length and Transfer-Encoding rejected",
    );
  }
  if (transferEncodings.length > 0) {
    throw new Error("unsupported Transfer-Encoding rejected");
  }
  if (contentLengths.length > 1) {
    throw new Error("duplicate Content-Length rejected");
  }
  const encodedLength = contentLengths[0] ?? "0";
  if (!/^(?:0|[1-9][0-9]*)$/u.test(encodedLength)) {
    throw new Error("non-canonical Content-Length rejected");
  }
  const contentLength = Number(encodedLength);
  if (!Number.isSafeInteger(contentLength) || contentLength > MAX_BODY_BYTES) {
    throw new Error("request body too large");
  }
  const bodyStart = headerEnd + 4;
  const messageEnd = bodyStart + contentLength;
  if (messageEnd !== rawRequest.length) {
    throw new Error("request must contain exactly one complete message");
  }
  return {
    method,
    path,
    body: Buffer.from(rawRequest.subarray(bodyStart, messageEnd)),
  };
}
