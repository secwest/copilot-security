function representativeUnflatten(original) {
  const result = {};
  for (const key of Object.keys(original)) {
    const segments = key.split(".");
    let recipient = result;
    while (segments.length > 1) {
      const segment = segments.shift();
      if (segment === "__proto__") break;
      recipient = recipient[segment] || (recipient[segment] = {});
    }
    if (segments.length === 1) recipient[segments[0]] = original[key];
  }
  return result;
}

representativeUnflatten({ "__proto__.isAdmin": true });
if ({}.isAdmin !== undefined) {
  throw new Error("flat 4.1.1 semantics did not block __proto__ traversal");
}
console.log("flat 4.1.1 unflatten semantics blocked __proto__ traversal");
