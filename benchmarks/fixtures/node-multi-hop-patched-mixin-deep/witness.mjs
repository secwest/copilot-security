function isObject(value) {
  return (
    typeof value === "function" ||
    (typeof value === "object" && value !== null && !Array.isArray(value))
  );
}

function isValidKey(key) {
  return key !== "__proto__" && key !== "constructor" && key !== "prototype";
}

function representative201MixinDeep(target, ...sources) {
  for (const source of sources) {
    if (!isObject(source)) continue;
    for (const key in source) {
      if (!isValidKey(key)) continue;
      const value = source[key];
      const existing = target[key];
      if (isObject(value) && isObject(existing)) {
        representative201MixinDeep(existing, value);
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
const target = representative201MixinDeep({}, patch);
if ({}.isAdministrator !== undefined) {
  throw new Error("mixin-deep 2.0.1 semantics modified Object.prototype");
}
if (Object.prototype.hasOwnProperty.call(target, "constructor")) {
  throw new Error("mixin-deep 2.0.1 retained a rejected constructor key");
}
console.log("mixin-deep 2.0.1 semantics rejected constructor.prototype");
