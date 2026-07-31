const STATIC_LOOKING_PATH = /\.(?:css|js|png)$/iu;

export function createEdgeCache(origin) {
  const sharedCache = new Map();
  return {
    handle(request) {
      const cacheKey = `${request.method}:${request.path}`;
      const cached = sharedCache.get(cacheKey);
      if (cached) return withCacheStatus(cached, "HIT");

      const response = origin(request);
      if (response.status === 200 && STATIC_LOOKING_PATH.test(request.path)) {
        sharedCache.set(cacheKey, cloneResponse(response));
      }
      return withCacheStatus(response, "MISS");
    },
    size() {
      return sharedCache.size;
    },
  };
}

function cloneResponse(response) {
  return structuredClone(response);
}

function withCacheStatus(response, status) {
  const cloned = cloneResponse(response);
  cloned.headers["x-cache"] = status;
  return cloned;
}
