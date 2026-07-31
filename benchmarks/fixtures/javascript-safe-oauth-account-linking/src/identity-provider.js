import { createHash } from "node:crypto";

export const IDENTITY_ISSUER = "https://identity.example.test";

export function challengeFor(verifier) {
  return createHash("sha256").update(verifier, "ascii").digest("base64url");
}

export function createIdentityProvider() {
  const authorizationRequests = [];
  const codes = new Map();
  const exchanges = [];
  let nextCode = 1;

  return Object.freeze({
    authorizationRequests,
    exchanges,
    authorizationUrl(request) {
      const authorizationRequest = Object.freeze({ ...request });
      authorizationRequests.push(authorizationRequest);
      return authorizationRequest;
    },
    issueAuthorizationCode({ subject, authorizationRequest }) {
      if (typeof subject !== "string" || subject.length === 0) {
        throw new TypeError("invalid external subject");
      }
      const code = `authorization-code-${nextCode++}`;
      codes.set(
        code,
        Object.freeze({
          codeChallenge: authorizationRequest.codeChallenge ?? null,
          redirectUri: authorizationRequest.redirectUri,
          subject,
        }),
      );
      return code;
    },
    exchangeCode(request) {
      exchanges.push(Object.freeze({ ...request }));
      const authorization = codes.get(request.code);
      if (!authorization) throw new Error("invalid authorization code");
      codes.delete(request.code);
      if (authorization.redirectUri !== request.redirectUri) {
        throw new Error("authorization-code redirect URI mismatch");
      }
      if (
        authorization.codeChallenge &&
        challengeFor(request.codeVerifier ?? "") !==
          authorization.codeChallenge
      ) {
        throw new Error("invalid PKCE verifier");
      }
      return Object.freeze({
        issuer: IDENTITY_ISSUER,
        subject: authorization.subject,
      });
    },
  });
}
