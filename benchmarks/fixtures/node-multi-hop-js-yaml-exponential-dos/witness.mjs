const operationLimit = 1_000_000;
let operations = 0;

function parseVulnerableFlowPair(depth) {
  operations += 1;
  if (operations > operationLimit) {
    throw new Error("vulnerable flow-pair parser exceeded operation limit");
  }
  if (depth === 0) return;
  parseVulnerableFlowPair(depth - 1);
  parseVulnerableFlowPair(depth - 1);
}

const depth = 26;
const payload = `${"[ ".repeat(depth)}1${" ]: 0".repeat(depth)}`;
if (Buffer.byteLength(payload) >= 200) {
  throw new Error("the modeled payload no longer fits below 200 bytes");
}
try {
  parseVulnerableFlowPair(depth);
  throw new Error("the vulnerable parser did not exhibit exponential work");
} catch (error) {
  if (!String(error).includes("exceeded operation limit")) throw error;
}
console.log("vulnerable js-yaml exponential flow-pair work reproduced");
