const entryCount = 4_000;
let lookups = 0;
const seen = Object.create(null);

for (let index = 0; index < entryCount; index += 1) {
  const key = `key${index}`;
  lookups += 1;
  if (Object.hasOwn(seen, key)) throw new Error("unexpected duplicate key");
  Object.defineProperty(seen, key, { value: true });
}

if (lookups !== entryCount) {
  throw new Error("patched js-yaml omap work was not linear");
}
console.log("patched js-yaml linear omap work reproduced");
