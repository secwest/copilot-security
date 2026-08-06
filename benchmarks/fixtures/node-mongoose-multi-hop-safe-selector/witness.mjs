const accounts = [
  { username: "administrator", role: "admin" },
  { username: "guest", role: "guest" },
];

function matches(value, selector) {
  if (selector !== null && typeof selector === "object") {
    if (Object.hasOwn(selector, "$eq")) return value === selector.$eq;
  }
  return value === selector;
}

const attackerValue = { $ne: null };
const filter = { username: { $eq: attackerValue } };
const account = accounts.find(({ username }) =>
  matches(username, filter.username),
);
if (account !== undefined)
  throw new Error("literal boundary accepted operator");
if (!accounts.some(({ username }) => matches(username, { $eq: "guest" }))) {
  throw new Error("literal selector rejected legitimate account");
}
console.log("safe selector rejected the operator and retained literal lookup");
