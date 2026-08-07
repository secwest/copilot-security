function defineProperty(object, name, value) {
  Object.defineProperty(object, name, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

function clone(value) {
  if (value === null || typeof value !== "object") return value;
  const result = Array.isArray(value) ? [] : {};
  for (const key of Object.keys(value)) defineProperty(result, key, clone(value[key]));
  return result;
}

function merge(merged, source) {
  for (const key of Object.keys(source)) {
    if (key in merged && merged[key] !== Object.getPrototypeOf(merged)) {
      defineProperty(merged, key, merge(merged[key], source[key]));
    } else {
      defineProperty(merged, key, clone(source[key]));
    }
  }
  return merged;
}

function representative101MergeOptions(...options) {
  let merged = { option: {} };
  for (const option of options) merged = merge(merged, { option });
  return merged.option;
}

const patch = JSON.parse('{"__proto__":{"isAdministrator":true}}');
const result = representative101MergeOptions({}, patch);
if ({}.isAdministrator !== undefined) {
  throw new Error("merge-options 1.0.1 semantics modified Object.prototype");
}
if (!Object.prototype.hasOwnProperty.call(result, "__proto__")) {
  throw new Error("patched witness did not retain __proto__ as own data");
}
if (Object.getPrototypeOf(result) !== Object.prototype) {
  throw new Error("patched witness replaced the returned object's prototype");
}
console.log("merge-options 1.0.1 semantics retained __proto__ as own data");
