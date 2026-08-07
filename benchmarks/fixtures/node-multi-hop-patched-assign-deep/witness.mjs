function isObject(value) {
  return (
    typeof value === "function" ||
    Object.prototype.toString.call(value) === "[object Object]"
  );
}

function isValidKey(key) {
  return key !== "__proto__" && key !== "constructor" && key !== "prototype";
}

function representative048AssignDeep(target, ...sources) {
  target = target || {};
  for (const source of sources) {
    if (!isObject(source)) continue;
    for (const key in source) {
      if (
        !isValidKey(key) ||
        !Object.prototype.hasOwnProperty.call(source, key)
      ) {
        continue;
      }
      const value = source[key];
      if (isObject(value)) {
        if (target[key] === undefined && typeof value === "function") {
          target[key] = value;
        }
        target[key] = representative048AssignDeep(target[key] || {}, value);
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
const target = representative048AssignDeep({}, patch);
if ({}.isAdministrator !== undefined) {
  throw new Error("assign-deep 0.4.8 semantics modified Object.prototype");
}
if (Object.prototype.hasOwnProperty.call(target, "constructor")) {
  throw new Error("assign-deep 0.4.8 retained a rejected constructor key");
}
console.log("assign-deep 0.4.8 semantics rejected constructor.prototype");
