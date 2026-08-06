import { storePreference } from "./src/storage.js";

delete Object.prototype.isAdministrator;
const stored = storePreference({
  namespace: "__proto__",
  key: "isAdministrator",
  value: true,
});
if (stored !== true) throw new Error("Map did not retain the preference");
if ({}.isAdministrator !== undefined) {
  throw new Error("Map-backed preference storage modified Object.prototype");
}
console.log("safe nested Map retained keys without prototype pollution");
