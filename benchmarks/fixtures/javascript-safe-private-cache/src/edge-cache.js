export function createEdgeCache(origin) {
  const sharedCache = new Map();
  return {
    handle(request) {
      const cacheKey = `${request.method}:${request.path}`;
      const cached = sharedCache.get(cacheKey);
      if (cached) return withCacheStatus(cached, "HIT");

      const response = origin(request);
      if (isExplicitlyPublic(request, response)) {
        sharedCache.set(cacheKey, cloneResponse(response));
      }
      return withCacheStatus(response, "MISS");
    },
    size() {
      return sharedCache.size;
    },
  };
}

function isExplicitlyPublic(request, response) {
  const cacheControl = String(response.headers["cache-control"] ?? "");
  return (
    request.method === "GET" &&
    request.cookies.sid === undefined &&
    response.status === 200 &&
    /(?:^|,)\s*public(?:\s*,|$)/iu.test(cacheControl) &&
    !/(?:^|,)\s*(?:private|no-store)(?:\s*,|$)/iu.test(cacheControl) &&
    response.headers["set-cookie"] === undefined
  );
}

function cloneResponse(response) {
  return structuredClone(response);
}

function withCacheStatus(response, status) {
  const cloned = cloneResponse(response);
  cloned.headers["x-cache"] = status;
  return cloned;
}
