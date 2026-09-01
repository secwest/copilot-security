const { default: cors } = await import(
  process.env.COPILOT_SECURITY_CORS_MODULE_URL ?? "cors"
);

const attackerOrigin = "https://attacker.example";
const headers = new Map();
const request = { headers: { origin: attackerOrigin }, method: "GET" };
const response = {
  getHeader(name) {
    return headers.get(name.toLowerCase());
  },
  setHeader(name, value) {
    headers.set(name.toLowerCase(), String(value));
  },
};

await new Promise((resolve, reject) => {
  cors({ origin: "https://app.example", credentials: true })(
    request,
    response,
    (error) => {
      if (error) reject(error);
      else resolve();
    },
  );
});

const allowOrigin = response.getHeader("Access-Control-Allow-Origin");
const allowCredentials =
  response.getHeader("Access-Control-Allow-Credentials") === "true";
const attackerCanRead = allowOrigin === attackerOrigin && allowCredentials;
if (attackerCanRead || allowOrigin !== "https://app.example") {
  throw new Error("the fixed-origin CORS control was not preserved");
}

console.log(JSON.stringify({
  allow_credentials: allowCredentials,
  allow_origin: allowOrigin,
  attacker_can_read: attackerCanRead,
  control: true,
}));
