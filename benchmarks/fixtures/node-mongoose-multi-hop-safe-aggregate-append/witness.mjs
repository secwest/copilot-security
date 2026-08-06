const accounts = [
  {
    _id: 1,
    username: "guest",
    displayName: "Guest",
    active: true,
    mfaSecret: "guest-mfa",
  },
  {
    _id: 2,
    username: "admin",
    displayName: "Administrator",
    active: true,
    mfaSecret: "admin-mfa",
  },
];

function executeFixedAppend(value) {
  if (typeof value !== "string")
    throw new TypeError("username must be a string");
  return accounts
    .filter(({ active }) => active)
    .filter(({ username }) => username === value)
    .map(({ username, displayName }) => ({ username, displayName }));
}

let rejected = false;
try {
  executeFixedAppend({ $ne: null });
} catch (error) {
  rejected = error instanceof TypeError;
}
const result = executeFixedAppend("guest");
if (
  !rejected ||
  result.length !== 1 ||
  result[0]?.username !== "guest" ||
  "mfaSecret" in result[0]
) {
  throw new Error("safe aggregate append boundary failed");
}
console.log(
  "safe aggregate append rejected operators and projected public data",
);
