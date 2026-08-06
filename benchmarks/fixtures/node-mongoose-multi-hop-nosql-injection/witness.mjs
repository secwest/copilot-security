const accounts = [
  { username: "administrator", role: "admin" },
  { username: "guest", role: "guest" },
];

function matches(value, selector) {
  if (selector !== null && typeof selector === "object") {
    if (Object.hasOwn(selector, "$ne")) return value !== selector.$ne;
    if (Object.hasOwn(selector, "$eq")) return value === selector.$eq;
  }
  return value === selector;
}

const attackerSelector = { $ne: null };
const account = accounts.find(({ username }) =>
  matches(username, attackerSelector),
);
if (account?.role !== "admin")
  throw new Error("selector bypass not reproduced");
console.log("vulnerable selector selected the administrator account");
