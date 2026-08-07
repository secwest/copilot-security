function isObject(value) {
  return typeof value === "object" && value !== null;
}

function validKey(key) {
  return key !== "__proto__" && key !== "constructor" && key !== "prototype";
}

function representative211RecursiveMerge(base, source) {
  for (const key of Object.keys(source)) {
    if (!validKey(key)) continue;
    const sourceValue = source[key];
    if (isObject(base[key]) && isObject(sourceValue)) {
      representative211RecursiveMerge(base[key], sourceValue);
    } else {
      base[key] = sourceValue;
    }
  }
  return base;
}

function representative211MergeRecursive(base, ...sources) {
  for (const source of sources) {
    if (!isObject(source)) continue;
    for (const key of Object.keys(source)) {
      if (!validKey(key)) continue;
      const sourceValue = source[key];
      if (isObject(base[key]) && isObject(sourceValue)) {
        representative211RecursiveMerge(base[key], sourceValue);
      } else {
        base[key] = sourceValue;
      }
    }
  }
  return base;
}

const patch = JSON.parse('{"deep":{"__proto__":{"isAdministrator":true}}}');
const target = representative211MergeRecursive({ deep: {} }, patch);
if ({}.isAdministrator !== undefined) {
  throw new Error("merge 2.1.1 semantics modified Object.prototype");
}
if (Object.prototype.hasOwnProperty.call(target.deep, "__proto__")) {
  throw new Error("merge 2.1.1 retained a rejected nested __proto__ key");
}
console.log("merge 2.1.1 nested recursive semantics rejected __proto__");
