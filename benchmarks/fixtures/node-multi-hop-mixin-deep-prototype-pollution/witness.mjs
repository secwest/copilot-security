function isObject(value) {
  return (
    typeof value === "function" ||
    (typeof value === "object" && value !== null && !Array.isArray(value))
  );
}

function representative200MixinDeep(target, ...sources) {
  for (const source of sources) {
    if (!isObject(source)) continue;
    for (const key in source) {
      if (key === "__proto__") continue;
      const value = source[key];
      const existing = target[key];
      if (isObject(value) && isObject(existing)) {
        representative200MixinDeep(existing, value);
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
try {
  representative200MixinDeep({}, patch);
  if ({}.isAdministrator !== true) {
    throw new Error(
      "mixin-deep 2.0.0 semantics did not modify Object.prototype",
    );
  }
  console.log("mixin-deep 2.0.0 semantics modified Object.prototype");
} finally {
  delete Object.prototype.isAdministrator;
}
