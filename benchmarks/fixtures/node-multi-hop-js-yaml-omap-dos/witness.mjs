const entryCount = 4_000;
let comparisons = 0;
const seen = [];

for (let index = 0; index < entryCount; index += 1) {
  const key = `key${index}`;
  for (const existing of seen) {
    comparisons += 1;
    if (existing === key) throw new Error("unexpected duplicate key");
  }
  seen.push(key);
}

const expectedComparisons = (entryCount * (entryCount - 1)) / 2;
if (comparisons !== expectedComparisons || comparisons < 7_000_000) {
  throw new Error("vulnerable js-yaml omap work was not quadratic");
}
console.log("vulnerable js-yaml quadratic omap work reproduced");
