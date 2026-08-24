let operations = 0;

function parsePatchedFlowPair(depth) {
  for (let level = depth; level >= 0; level -= 1) {
    operations += 1;
  }
}

const depth = 26;
const payload = `${"[ ".repeat(depth)}1${" ]: 0".repeat(depth)}`;
if (Buffer.byteLength(payload) >= 200) {
  throw new Error("the modeled payload no longer fits below 200 bytes");
}
parsePatchedFlowPair(depth);
if (operations !== depth + 1) {
  throw new Error("the patched parser did not retain linear event work");
}
console.log("patched js-yaml linear flow-pair work reproduced");
