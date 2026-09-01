const maximumAttempts = 5;
let consumed = 0;
let passwordVerifications = 0;
let rateLimited = 0;

for (let attempt = 0; attempt < 6; attempt += 1) {
  const pluginRegistered = false;
  if (pluginRegistered && consumed >= maximumAttempts) {
    rateLimited += 1;
    continue;
  }
  if (pluginRegistered) consumed += 1;
  passwordVerifications += 1;
}

if (passwordVerifications !== 6 || rateLimited !== 0) {
  throw new Error(
    "the inert route configuration unexpectedly limited attempts",
  );
}

console.log(
  JSON.stringify({
    control: false,
    password_verifications: passwordVerifications,
    rate_limited_requests: rateLimited,
  }),
);
