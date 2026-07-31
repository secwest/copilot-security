export function createHttpClient(resolver, transport) {
  return {
    async get(target, options) {
      if (options.redirect !== "error") {
        throw new Error("redirects must be disabled");
      }

      const addresses = await resolver.resolveAll(target.hostname);
      if (addresses.length === 0)
        throw new Error("destination did not resolve");

      return transport.request({
        connectAddress: addresses[0],
        hostHeader: target.host,
        path: `${target.pathname}${target.search}`,
        redirect: options.redirect,
        tlsServerName: target.hostname,
      });
    },
  };
}
