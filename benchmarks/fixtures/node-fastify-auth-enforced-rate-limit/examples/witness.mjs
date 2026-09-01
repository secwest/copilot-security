const maximumAttempts = 5;
let consumed = 0;
let passwordVerifications = 0;
let rateLimited = 0;

for (let attempt = 0; attempt < 6; attempt += 1) {
  const pluginRegistered = true;
  if (pluginRegistered && consumed >= maximumAttempts) {
    rateLimited += 1;
    continue;
  }
  if (pluginRegistered) consumed += 1;
  passwordVerifications += 1;
}

if (passwordVerifications !== 5 || rateLimited !== 1) {
  throw new Error(
    "the registered limiter did not enforce the attempt boundary",
  );
}

console.log(
  JSON.stringify({
    control: true,
    password_verifications: passwordVerifications,
    rate_limited_requests: rateLimited,
  }),
);
