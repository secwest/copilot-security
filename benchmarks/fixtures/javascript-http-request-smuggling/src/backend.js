export function processBackendPipeline(rawRequests, state) {
  let offset = 0;
  let processed = 0;
  while (offset < rawRequests.length) {
    const request = parseBackendRequest(rawRequests.subarray(offset));
    dispatch(request, state);
    offset += request.consumedBytes;
    processed += 1;
  }
  return processed;
}

function parseBackendRequest(rawRequest) {
  const headerEnd = rawRequest.indexOf("\r\n\r\n");
  if (headerEnd < 0) throw new Error("incomplete request headers");
  const lines = rawRequest
    .subarray(0, headerEnd)
    .toString("latin1")
    .split("\r\n");
  const [method, path] = lines.shift().split(" ");
  const headers = new Map(
    lines.map((line) => {
      const separator = line.indexOf(":");
      return [
        line.slice(0, separator).trim().toLowerCase(),
        line.slice(separator + 1).trim(),
      ];
    }),
  );
  const bodyStart = headerEnd + 4;
  const transferEncoding = headers.get("transfer-encoding")?.toLowerCase();
  const consumedBytes =
    transferEncoding === "chunked"
      ? bodyStart + consumeChunkedBody(rawRequest.subarray(bodyStart))
      : bodyStart + Number(headers.get("content-length") ?? 0);
  if (consumedBytes > rawRequest.length)
    throw new Error("incomplete request body");
  return { method, path, consumedBytes };
}

function consumeChunkedBody(body) {
  let offset = 0;
  while (true) {
    const lineEnd = body.indexOf("\r\n", offset);
    if (lineEnd < 0) throw new Error("incomplete chunk size");
    const size = Number.parseInt(
      body.subarray(offset, lineEnd).toString("ascii"),
      16,
    );
    if (!Number.isSafeInteger(size) || size < 0)
      throw new Error("invalid chunk size");
    offset = lineEnd + 2;
    if (size === 0) {
      if (body.subarray(offset, offset + 2).toString("ascii") !== "\r\n") {
        throw new Error("invalid chunk terminator");
      }
      return offset + 2;
    }
    offset += size;
    if (body.subarray(offset, offset + 2).toString("ascii") !== "\r\n") {
      throw new Error("invalid chunk data");
    }
    offset += 2;
  }
}

function dispatch(request, state) {
  if (request.method === "POST" && request.path === "/submit") {
    state.submissions += 1;
  }
  if (request.method === "DELETE" && request.path === "/admin/records") {
    state.records = [];
    state.adminDeletes += 1;
  }
}
