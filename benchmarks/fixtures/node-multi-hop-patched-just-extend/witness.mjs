function isCloneable(value) {
  return Array.isArray(value) ||
    Object.prototype.toString.call(value) === "[object Object]";
}

function representative401Extend(deep, target, ...sources) {
  for (const source of sources) {
    for (const key in source) {
      if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
      const value = source[key];
      if (deep && isCloneable(value)) {
        const base = Array.isArray(value) ? [] : {};
        target[key] = representative401Extend(
          true,
          Object.prototype.hasOwnProperty.call(target, key)
            ? target[key]
            : base,
          value,
        );
      } else {
        target[key] = value;
      }
    }
  }
  return target;
}

const patch = JSON.parse('{"__proto__":{"isAdministrator":true}}');
const target = representative401Extend(true, {}, patch);
if ({}.isAdministrator !== undefined) {
  throw new Error("just-extend 4.0.1 semantics modified Object.prototype");
}
if (target.isAdministrator !== true) {
  throw new Error("witness did not preserve the target-local prototype effect");
}
console.log("just-extend 4.0.1 semantics blocked global prototype traversal");
