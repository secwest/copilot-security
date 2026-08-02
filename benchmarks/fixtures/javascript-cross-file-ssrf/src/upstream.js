const MAX_PREVIEW_BYTES = 64 * 1024;

export async function fetchPreview(target, response) {
  const upstream = await fetch(target, {
    redirect: "follow",
    signal: AbortSignal.timeout(2_000),
  });
  return response.send(await readLimitedBody(upstream));
}

async function readLimitedBody(upstream) {
  if (upstream.body === null) return Buffer.alloc(0);
  const reader = upstream.body.getReader();
  const chunks = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > MAX_PREVIEW_BYTES) {
        await reader.cancel("preview response exceeds size limit");
        throw new Error("preview response exceeds size limit");
      }
      chunks.push(Buffer.from(value));
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, length);
}
