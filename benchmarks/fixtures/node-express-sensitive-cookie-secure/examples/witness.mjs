const modeledCookie = {
  name: "session",
  value: "modeled-session-value",
  httpOnly: true,
  secure: true,
  sameSite: "Lax",
};

const attributes = [
  `${modeledCookie.name}=${modeledCookie.value}`,
  modeledCookie.httpOnly ? "HttpOnly" : undefined,
  modeledCookie.secure ? "Secure" : undefined,
  `SameSite=${modeledCookie.sameSite}`,
].filter(Boolean);
const setCookie = attributes.join("; ");
const permitsHttpTransport = !attributes.includes("Secure");

if (permitsHttpTransport || !setCookie.includes("HttpOnly")) {
  throw new Error("the modeled Secure transport control was not preserved");
}

console.log(
  JSON.stringify({
    control: true,
    permits_http_transport: permitsHttpTransport,
    set_cookie: setCookie,
  }),
);
