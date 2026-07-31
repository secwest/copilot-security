import { allAddressesPublic } from "./network-policy.js";

export function createHttpClient(transport) {
  return {
    async getPinned(target, options) {
      if (options.redirect !== "error") {
        throw new Error("redirects must be disabled");
      }
      if (!allAddressesPublic([options.connectAddress])) {
        throw new Error("a validated public connection address is required");
      }

      return transport.request({
        connectAddress: options.connectAddress,
        hostHeader: target.host,
        path: `${target.pathname}${target.search}`,
        redirect: options.redirect,
        tlsServerName: target.hostname,
      });
    },
  };
}
