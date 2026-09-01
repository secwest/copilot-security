const cookies = [
  {
    name: "__Host-session",
    value: "modeled-session-value",
    httpOnly: true,
  },
];

const documentCookie = cookies
  .filter((cookie) => !cookie.httpOnly)
  .map((cookie) => `${cookie.name}=${cookie.value}`)
  .join("; ");

if (documentCookie.includes("modeled-session-value")) {
  throw new Error("the HttpOnly session value remained browser-readable");
}

console.log(
  JSON.stringify({
    control: true,
    browser_visible_session_values: 0,
    document_cookie: documentCookie,
  }),
);
