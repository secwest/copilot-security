function representativeInheritedDelete(target, path) {
  const parts = path.split(".");
  while (parts.length > 1) {
    const key = String(parts.shift());
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      throw new Error("For security reasons, magic properties cannot be used");
    }
    target = target[key];
  }
  delete target[parts[0]];
}

const original = Object.prototype.toString;
let blocked = false;
try {
  representativeInheritedDelete({}, "__proto__.toString");
} catch {
  blocked = true;
}
if (!blocked || Object.prototype.toString !== original) {
  throw new Error("object-path 0.11.8 semantics did not block deletion");
}
console.log("object-path 0.11.8 rejected inherited magic-property access");
