import { buildOptions } from "./src/storage.js";

const patch = JSON.parse('{"__proto__":{"isAdministrator":true}}');
const options = buildOptions(patch);
if (Object.getPrototypeOf(options) !== null) {
  throw new Error("assignment target unexpectedly acquired a prototype");
}
if (!Object.hasOwn(options, "__proto__")) {
  throw new Error(
    "null-prototype target did not retain the source key as data",
  );
}
if (options.isAdministrator !== undefined) {
  throw new Error("null-prototype options inherited attacker state");
}
if (options.mode !== "strict")
  throw new Error("fixed defaults were not retained");
console.log("safe null-prototype target retained __proto__ as ordinary data");
