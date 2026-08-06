const forbidden = new Set(["__proto__", "constructor", "prototype"]);

function representativePatchedMerge(target, source) {
  for (const key of Object.keys(source)) {
    if (forbidden.has(key)) continue;
    const value = source[key];
    if (value !== null && typeof value === "object") {
      if (target[key] === undefined) target[key] = {};
      representativePatchedMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

const patch = JSON.parse(
  '{"constructor":{"prototype":{"isAdministrator":true}}}',
);
representativePatchedMerge({}, patch);
if ({}.isAdministrator !== undefined) {
  throw new Error("lock-resolved patched merge modified Object.prototype");
}
console.log("lock-resolved patched merge rejected the prototype path");
