const cookies = [
  {
    name: "__Host-session",
    value: "modeled-session-value",
    httpOnly: false,
  },
];

const documentCookie = cookies
  .filter((cookie) => !cookie.httpOnly)
  .map((cookie) => `${cookie.name}=${cookie.value}`)
  .join("; ");

if (!documentCookie.includes("__Host-session=modeled-session-value")) {
  throw new Error(
    "the browser-readable session cookie was unexpectedly hidden",
  );
}

console.log(
  JSON.stringify({
    control: false,
    browser_visible_session_values: 1,
    document_cookie: documentCookie,
  }),
);
