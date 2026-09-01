const moduleUrl = process.env.COPILOT_SECURITY_JSONWEBTOKEN_MODULE_URL;
if (!moduleUrl) throw new Error("missing jsonwebtoken module URL");
const imported = await import(moduleUrl);
const jwt = imported.default ?? imported;

const encode = (value) =>
  Buffer.from(JSON.stringify(value)).toString("base64url");
const forged = `${encode({ alg: "none", typ: "JWT" })}.${encode({
  role: "admin",
  iss: "https://attacker.example",
  aud: "admin-api",
})}.`;
const claims = jwt.decode(forged);
const authorizationGranted = claims?.role === "admin";

process.stdout.write(
  `${JSON.stringify({
    authorization_granted: authorizationGranted,
    control: false,
    signature_verified: false,
  })}\n`,
);
