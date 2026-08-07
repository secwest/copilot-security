function representativeUnflatten(original, patched) {
  const result = {};
  for (const key of Object.keys(original)) {
    const segments = key.split(".");
    let recipient = result;
    while (segments.length > 1) {
      const segment = segments.shift();
      if (patched && segment === "__proto__") break;
      recipient = recipient[segment] || (recipient[segment] = {});
    }
    if (segments.length === 1) recipient[segments[0]] = original[key];
  }
  return result;
}

const hostile = { "__proto__.isAdmin": true };
try {
  representativeUnflatten(hostile, false);
  if ({}.isAdmin !== true) {
    throw new Error("flat 4.1.0 semantics did not modify Object.prototype");
  }
  console.log("flat 4.1.0 unflatten semantics modified Object.prototype");
} finally {
  delete Object.prototype.isAdmin;
}

representativeUnflatten(hostile, true);
if ({}.isAdmin !== undefined) {
  throw new Error("flat 4.1.1 semantics did not block __proto__ traversal");
}
console.log("flat 4.1.1 unflatten semantics blocked __proto__ traversal");
