const forbidden = new Set(["__proto__", "constructor", "prototype"]);

function representativePatchedExtend(deep, target, ...sources) {
  for (const source of sources) {
    for (const key of Object.keys(source)) {
      if (forbidden.has(key)) continue;
      const value = source[key];
      if (deep && value !== null && typeof value === "object") {
        if (target[key] === undefined) target[key] = {};
        representativePatchedExtend(true, target[key], value);
      } else {
        target[key] = value;
      }
    }
  }
  return target;
}

const patch = JSON.parse(
  '{"constructor":{"prototype":{"isAdministrator":true}}}',
);
representativePatchedExtend(true, {}, patch);
if ({}.isAdministrator !== undefined) {
  throw new Error("patched extend deep merge modified Object.prototype");
}
console.log("patched extend deep merge rejected the prototype path");
