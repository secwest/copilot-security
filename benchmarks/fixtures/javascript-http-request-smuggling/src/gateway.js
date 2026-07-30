export function authorizeAndForward(rawRequest, processBackendPipeline, state) {
  const visible = parseContentLengthRequest(rawRequest);
  if (visible.path.startsWith("/admin/")) {
    throw new Error("gateway authorization rejected administrative request");
  }
  return processBackendPipeline(rawRequest, state);
}

function parseContentLengthRequest(rawRequest) {
  const headerEnd = rawRequest.indexOf("\r\n\r\n");
  if (headerEnd < 0) throw new Error("incomplete request headers");
  const lines = rawRequest
    .subarray(0, headerEnd)
    .toString("latin1")
    .split("\r\n");
  const [, path] = lines[0].split(" ");
  const contentLengthHeader = lines.find((line) =>
    line.toLowerCase().startsWith("content-length:"),
  );
  const contentLength = Number(
    contentLengthHeader?.split(":", 2)[1]?.trim() ?? 0,
  );
  const messageEnd = headerEnd + 4 + contentLength;
  if (
    !Number.isSafeInteger(contentLength) ||
    messageEnd !== rawRequest.length
  ) {
    throw new Error("invalid Content-Length framing");
  }
  return { path, messageEnd };
}
