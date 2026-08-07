function isHash(value) {
  return Object.prototype.toString.call(value) === "[object Object]";
}

function getProperty(object, name) {
  if (name === "__proto__" && !Object.prototype.hasOwnProperty.call(object, name)) {
    return undefined;
  }
  return Object.getOwnPropertyDescriptor(object, name)?.value;
}

function setProperty(object, name, value) {
  Object.defineProperty(object, name, {
    value,
    writable: true,
    enumerable: true,
    configurable: true,
  });
}

function representative201NodeExtend(deep, target, ...sources) {
  for (const source of sources) {
    for (const name in source) {
      const existing = getProperty(target, name);
      const copy = getProperty(source, name);
      if (target === copy) continue;
      if (deep && copy && (isHash(copy) || Array.isArray(copy))) {
        const clone = Array.isArray(copy)
          ? Array.isArray(existing)
            ? existing
            : []
          : existing && isHash(existing)
            ? existing
            : {};
        setProperty(
          target,
          name,
          representative201NodeExtend(true, clone, copy),
        );
      } else if (copy !== undefined) {
        setProperty(target, name, copy);
      }
    }
  }
  return target;
}

const patch = JSON.parse('{"__proto__":{"isAdministrator":true}}');
const target = representative201NodeExtend(true, {}, patch);
if ({}.isAdministrator !== undefined) {
  throw new Error("node.extend 2.0.1 semantics modified Object.prototype");
}
if (!Object.prototype.hasOwnProperty.call(target, "__proto__")) {
  throw new Error("patched witness did not retain __proto__ as own data");
}
if (Object.getPrototypeOf(target) !== Object.prototype) {
  throw new Error("patched witness replaced the target prototype");
}
if (target.__proto__.isAdministrator !== true) {
  throw new Error("patched witness did not retain the nested own data");
}
console.log("node.extend 2.0.1 semantics retained __proto__ as own data");
