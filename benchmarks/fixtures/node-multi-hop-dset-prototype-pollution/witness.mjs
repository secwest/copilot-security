function representativeDset(target, keys, value, patched) {
  let index = 0;
  while (index < keys.length) {
    const key = patched ? String(keys[index++]) : keys[index++];
    if (key === "__proto__" || key === "constructor" || key === "prototype") {
      break;
    }
    target[key] = index === keys.length ? value : target[key] || {};
    target = target[key];
  }
}

function representativeMerge(target, source, patched) {
  for (const key of Object.keys(source)) {
    if (
      patched &&
      (key === "__proto__" || key === "constructor" || key === "prototype")
    ) {
      continue;
    }
    if (target[key] && source[key] && typeof source[key] === "object") {
      representativeMerge(target[key], source[key], patched);
    } else {
      target[key] = source[key];
    }
  }
}

try {
  representativeDset({}, [["__proto__"], "isAdmin"], true, false);
  if ({}.isAdmin !== true) {
    throw new Error(
      "dset 3.1.3 path semantics did not modify Object.prototype",
    );
  }
  console.log("dset 3.1.3 nested path semantics modified Object.prototype");
} finally {
  delete Object.prototype.isAdmin;
}

representativeDset({}, [["__proto__"], "isAdmin"], true, true);
if ({}.isAdmin !== undefined) {
  throw new Error("dset 3.1.4 path semantics accepted the nested segment");
}
console.log("dset 3.1.4 coerced and blocked the nested dangerous segment");

const hostile = JSON.parse('{"__proto__":{"mergedAdmin":true}}');
try {
  representativeMerge({ profile: {} }.profile, hostile, false);
  if ({}.mergedAdmin !== true) {
    throw new Error(
      "dset/merge 3.1.1 semantics did not modify Object.prototype",
    );
  }
  console.log("dset/merge 3.1.1 value semantics modified Object.prototype");
} finally {
  delete Object.prototype.mergedAdmin;
}

representativeMerge({ profile: {} }.profile, hostile, true);
if ({}.mergedAdmin !== undefined) {
  throw new Error("dset/merge 3.1.2 semantics accepted the dangerous value");
}
console.log("dset/merge 3.1.2 blocked the dangerous merge value");
