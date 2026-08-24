import { createRequire } from "node:module";
import NextAuth from "next-auth";

const require = createRequire(import.meta.url);
const version = require("next-auth/package.json").version;
process.env.AUTH_SECRET = "benchmark-only-secret";
process.env.AUTH_URL = "https://app.example.test/api/auth";
process.env.AUTH_TRUST_HOST = "true";

const brokenConfig = {
  providers: [
    {
      id: "deployment-oidc",
      name: "Deployment OIDC",
      type: "oidc",
      clientId: "deployment-client",
      clientSecret: "deployment-secret",
    },
  ],
};
const { auth } = NextAuth(brokenConfig);
let observedAuth = "callback-not-called";
const handler = auth((request) => {
  observedAuth = request.auth;
  return new Response(null, { status: request.auth ? 204 : 401 });
});
const request = new Request("https://app.example.test/private");
request.nextUrl = new URL(request.url);
const response = await handler(request, {});

console.log(
  JSON.stringify({
    version,
    allowed: response.status === 204,
    responseStatus: response.status,
    authWasNull: observedAuth === null,
    authWasTruthyError:
      typeof observedAuth === "object" &&
      observedAuth !== null &&
      typeof observedAuth.message === "string",
    listenerOpened: false,
  }),
);
