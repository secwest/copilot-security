const DEFAULT_FILENAME = "quarterly-report.csv";

export function createReportApplication(publicReport) {
  return {
    handle(request) {
      const filename = String(request.query.filename ?? DEFAULT_FILENAME);
      if (filename.length > 256) return serializeError(400, "invalid_filename");

      return [
        "HTTP/1.1 200 OK",
        "Content-Type: text/csv; charset=utf-8",
        `Content-Disposition: attachment; filename="${filename}"`,
        `Content-Length: ${Buffer.byteLength(publicReport)}`,
        "",
        publicReport,
      ].join("\r\n");
    },
  };
}

export function deliverThroughGateway(rawResponse, internalFiles) {
  const boundary = rawResponse.indexOf("\r\n\r\n");
  if (boundary < 0) throw new Error("malformed upstream response");

  const head = rawResponse.slice(0, boundary);
  const body = rawResponse.slice(boundary + 4);
  const [statusLine, ...headerLines] = head.split("\r\n");
  const headers = new Map();
  for (const line of headerLines) {
    const separator = line.indexOf(":");
    if (separator <= 0) throw new Error("malformed upstream header");
    headers.set(
      line.slice(0, separator).trim().toLowerCase(),
      line.slice(separator + 1).trim(),
    );
  }

  const internalTarget = headers.get("x-accel-redirect");
  if (internalTarget !== undefined) {
    const protectedBody = internalFiles.get(internalTarget);
    if (protectedBody === undefined) {
      return { status: 404, headers, body: "not_found" };
    }
    return { status: 200, headers, body: protectedBody };
  }

  return {
    status: Number(statusLine.split(" ")[1]),
    headers,
    body,
  };
}

function serializeError(status, body) {
  return [
    `HTTP/1.1 ${status} Bad Request`,
    "Content-Type: text/plain; charset=utf-8",
    `Content-Length: ${Buffer.byteLength(body)}`,
    "",
    body,
  ].join("\r\n");
}
