function representativeDset(target, keys, value) {
  let index = 0;
  while (index < keys.length) {
    const key = String(keys[index++]);
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      break;
    }
    target[key] = index === keys.length ? value : target[key] || {};
    target = target[key];
  }
}

representativeDset({}, [["__proto__"], "isAdmin"], true);
if ({}.isAdmin !== undefined) {
  throw new Error("dset 3.1.4 path semantics accepted the nested segment");
}
console.log("dset 3.1.4 coerced and blocked the nested dangerous segment");
