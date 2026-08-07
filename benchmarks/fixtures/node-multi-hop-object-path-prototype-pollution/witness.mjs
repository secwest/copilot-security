function representativeInheritedDelete(target, path, patched) {
  const parts = path.split(".");
  while (parts.length > 1) {
    const key = String(parts.shift());
    if (
      patched &&
      (key === "__proto__" || key === "constructor" || key === "prototype")
    ) {
      throw new Error("For security reasons, magic properties cannot be used");
    }
    target = target[key];
  }
  delete target[parts[0]];
}

const original = Object.prototype.toString;
try {
  representativeInheritedDelete({}, "__proto__.toString", false);
  if (Object.hasOwn(Object.prototype, "toString")) {
    throw new Error("object-path 0.11.7 semantics did not delete toString");
  }
  let failed = false;
  try {
    String({});
  } catch {
    failed = true;
  }
  if (!failed) {
    throw new Error("deleted Object.prototype method had no coercion effect");
  }
  console.log("object-path 0.11.7 inherited del broke object coercion");
} finally {
  Object.defineProperty(Object.prototype, "toString", {
    value: original,
    configurable: true,
    writable: true,
  });
}

let blocked = false;
try {
  representativeInheritedDelete({}, "__proto__.toString", true);
} catch {
  blocked = true;
}
if (!blocked || Object.prototype.toString !== original) {
  throw new Error("object-path 0.11.8 semantics did not block deletion");
}
console.log("object-path 0.11.8 rejected inherited magic-property access");
