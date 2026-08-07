function safeGetProperty(object, property) {
  return property === "__proto__" ? undefined : object[property];
}

function representativePatchedDeepExtend(target, ...sources) {
  for (const source of sources) {
    for (const key of Object.keys(source)) {
      const current = safeGetProperty(target, key);
      const value = safeGetProperty(source, key);
      if (value !== null && typeof value === "object") {
        if (current === null || typeof current !== "object") target[key] = {};
        representativePatchedDeepExtend(target[key], value);
      } else {
        target[key] = value;
      }
    }
  }
  return target;
}

const patch = JSON.parse('{"__proto__":{"isAdministrator":true}}');
representativePatchedDeepExtend({}, patch);
if ({}.isAdministrator !== undefined) {
  throw new Error("patched deep-extend modified Object.prototype");
}
console.log("patched deep-extend rejected the prototype path");
